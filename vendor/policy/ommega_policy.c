/*
 * ommega-policy —— 把 allow / permissive 语句打进内核正在用的 SELinux policy。
 *
 * 读 /sys/fs/selinux/policy → 改 policydb → 单次 write 到 /sys/fs/selinux/load。
 *
 * 语法：
 *     allow <类型>{集合} <类型>{集合} <类> <权限>{集合}|*
 *     permissive <类型>{集合}
 * 集合可以写单个名字或 `{ a b c }`；目标写 `self` 表示源类型自己。类型/类/权限在
 * 策略里不存在时跳过该名字，不算错。
 *
 * 用法：
 *   ommega-policy --live --apply FILE            # 改完写回内核
 *   ommega-policy --check --apply FILE           # 只判缺不缺，不写
 *   ommega-policy --save OUT --apply FILE        # 只落盘
 *   ommega-policy --load IN --live --apply FILE  # 换输入
 *
 * `--check` 退出码：0 = 规则已全在，3 = 缺规则，1 = 出错。
 * 依赖 AOSP libsepol 的 core（policydb 读写 + avtab / ebitmap）。
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sepol/policydb/avtab.h>
#include <sepol/policydb/ebitmap.h>
#include <sepol/policydb/hashtab.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/symtab.h>

#define LIVE_POLICY "/sys/fs/selinux/policy"
#define LIVE_LOAD "/sys/fs/selinux/load"

#define MAX_TOKENS 512
#define MAX_NAMES 64
#define MAX_LINE 4096

struct nameset {
    const char *name[MAX_NAMES];
    int count;
};

static int g_verbose;

static void note(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

static void note(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

/* ---------------------------------------------------------------- 文件 */

static int read_whole_file(const char *path, char **out, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    long size;
    char *buf;

    if (!f)
        return -1;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return -1;
    }
    size = ftell(f);
    if (size <= 0) {
        fclose(f);
        return -1;
    }
    rewind(f);
    buf = malloc((size_t)size);
    if (!buf) {
        fclose(f);
        return -1;
    }
    if (fread(buf, 1, (size_t)size, f) != (size_t)size) {
        free(buf);
        fclose(f);
        return -1;
    }
    fclose(f);
    *out = buf;
    *out_len = (size_t)size;
    return 0;
}

/* ---------------------------------------------------------------- 词法 */

/* 按空白切词，`{` `}` 各自算一个词。返回词数，-1 表示太多。
 *
 * 先在 tokbuf 里给括号两边补空格，再切：直接就地换 `\0` 的话，括号后面紧跟着
 * 下一个词时（`{read`）会把括号当成「{read」这么一个词，之前就是这么读错的。 */
static char tokbuf[MAX_LINE * 2];

static int tokenize(char *line, char **tok, int max)
{
    size_t out = 0;
    char *p;
    char *q;
    int n = 0;

    for (p = line; *p && out + 4 < sizeof(tokbuf); p++) {
        if (*p == '{' || *p == '}') {
            tokbuf[out++] = ' ';
            tokbuf[out++] = *p;
            tokbuf[out++] = ' ';
        } else {
            tokbuf[out++] = *p;
        }
    }
    tokbuf[out] = '\0';

    q = tokbuf;
    while (*q) {
        while (*q == ' ' || *q == '\t' || *q == '\r' || *q == '\n')
            q++;
        if (!*q)
            break;
        if (n >= max)
            return -1;
        tok[n++] = q;
        while (*q && *q != ' ' && *q != '\t' && *q != '\r' && *q != '\n')
            q++;
        if (*q)
            *q++ = '\0';
    }
    return n;
}

/*
 * 取一个名字集合：单个词，或者 `{ a b c }`。
 * 返回 0 成功，-1 语法错误。
 */
static int parse_nameset(char **tok, int ntok, int *pos, struct nameset *set)
{
    int i = *pos;

    set->count = 0;
    if (i >= ntok)
        return -1;
    if (strcmp(tok[i], "{") != 0) {
        /* 单个名字；顺手挡一下把 `}` 当名字的情况 */
        if (strcmp(tok[i], "}") == 0)
            return -1;
        set->name[set->count++] = tok[i];
        *pos = i + 1;
        return 0;
    }
    i++;
    while (i < ntok && strcmp(tok[i], "}") != 0) {
        if (set->count >= MAX_NAMES)
            return -1;
        set->name[set->count++] = tok[i];
        i++;
    }
    if (i >= ntok || set->count == 0)
        return -1;
    *pos = i + 1;
    return 0;
}

/* ------------------------------------------------------------ 类型/类/权限 */

static type_datum_t *find_type(policydb_t *p, const char *name)
{
    type_datum_t *t = hashtab_search(p->p_types.table, (hashtab_key_t)name);

    if (!t)
        return NULL;
    /* 别名指向实体类型；attribute 我们不展开，直接当错误处理。 */
    if (t->flavor == TYPE_ATTRIB)
        return NULL;
    return t;
}

static class_datum_t *find_class(policydb_t *p, const char *name)
{
    return hashtab_search(p->p_classes.table, (hashtab_key_t)name);
}

/* 一个类定义了多少个权限（common 的 + 类自己的），给 `*` 用。 */
static uint32_t class_perm_count(class_datum_t *cls)
{
    uint32_t count = cls->permissions.nprim;

    if (cls->comdatum)
        count += cls->comdatum->permissions.nprim;
    return count;
}

/*
 * 权限名 -> 位图。值是 1-based 的序号，位就是 `1 << (value - 1)`：
 * 带 common 的类，类自己的权限序号从 common 之后接着编，所以不用再加偏移。
 */
static int perm_bit(policydb_t *p, class_datum_t *cls, const char *name, uint32_t *bit)
{
    perm_datum_t *perm = hashtab_search(cls->permissions.table, (hashtab_key_t)name);

    if (!perm && cls->comdatum)
        perm = hashtab_search(cls->comdatum->permissions.table, (hashtab_key_t)name);
    if (!perm) {
        (void)p;
        return -1;
    }
    if (perm->s.value == 0 || perm->s.value > 32)
        return -1;
    *bit = 1u << (perm->s.value - 1);
    return 0;
}

/* ------------------------------------------------------------ 插规则 */

static int add_allow(policydb_t *p, uint16_t src, uint16_t tgt, uint16_t cls,
                     uint32_t perms)
{
    avtab_key_t key;
    avtab_ptr_t node;
    avtab_datum_t datum;

    if (perms == 0)
        return 0;

    memset(&key, 0, sizeof(key));
    key.source_type = src;
    key.target_type = tgt;
    key.target_class = cls;
    key.specified = AVTAB_ALLOWED;

    /* 已经有的规则就地补位：重复 apply 是幂等的，不然第二条会把第一条覆盖掉。 */
    node = avtab_search_node(&p->te_avtab, &key);
    if (node) {
        uint32_t before = node->datum.data;

        node->datum.data |= perms;
        return node->datum.data != before ? 1 : 0;
    }

    memset(&datum, 0, sizeof(datum));
    datum.data = perms;
    if (avtab_insert(&p->te_avtab, &key, &datum) != 0)
        return -1;
    return 1;
}

/* `permissive <类型>{集合}`：把这些类型标成 permissive。类型不存在不算错，跟 allow 一样跳过。 */
static int apply_permissive(policydb_t *p, char **tok, int ntok, int pos)
{
    struct nameset types;
    int i;
    int changed = 0;

    if (parse_nameset(tok, ntok, &pos, &types) != 0) {
        note("ommega-policy: permissive 的类型那一段看不懂");
        return -1;
    }
    for (i = 0; i < types.count; i++) {
        type_datum_t *t = find_type(p, types.name[i]);

        if (!t) {
            note("ommega-policy: 这份 policy 里没有类型 %s，跳过", types.name[i]);
            continue;
        }
        if (ebitmap_get_bit(&p->permissive_map, t->s.value))
            continue;
        if (ebitmap_set_bit(&p->permissive_map, t->s.value, 1) != 0) {
            note("ommega-policy: 置 permissive 位失败（%s，errno=%d）",
                 types.name[i], errno);
            return -1;
        }
        changed++;
    }
    return changed;
}

/* 一条规则。返回值：1 加了/改了规则，0 没动（已经有或全跳过），-1 出错。
 *
 * 类型/类/权限在 policy 里不存在时**不算错**：sepolicy.rule 本来就是「把各种机型的
 * 域名都列上、比实际存在的挑自己的那份用」，ksud/magiskpolicy 也是跳过。所以这里
 * 只记一行 note、跳过那个名字，整份文件接着往下打。 */
static int apply_statement(policydb_t *p, char *line)
{
    char *tok[MAX_TOKENS];
    struct nameset srcs, tgts, perms;
    class_datum_t *cls;
    const char *cls_name;
    int ntok, pos = 0;
    int changed = 0;
    int i, j;
    uint32_t mask = 0;

    /* 去注释 */
    {
        char *hash = strchr(line, '#');

        if (hash)
            *hash = '\0';
    }

    ntok = tokenize(line, tok, MAX_TOKENS);
    if (ntok <= 0)
        return 0;
    if (strcmp(tok[pos], "permissive") == 0)
        return apply_permissive(p, tok, ntok, pos + 1);
    if (strcmp(tok[pos], "allow") != 0) {
        note("ommega-policy: 不认的语句（只支持 allow / permissive）：%s", tok[pos]);
        return -1;
    }
    pos++;
    if (parse_nameset(tok, ntok, &pos, &srcs) != 0) {
        note("ommega-policy: 源类型那一段看不懂");
        return -1;
    }
    if (parse_nameset(tok, ntok, &pos, &tgts) != 0) {
        note("ommega-policy: 目标类型那一段看不懂");
        return -1;
    }
    if (pos >= ntok) {
        note("ommega-policy: 少了类名");
        return -1;
    }
    cls_name = tok[pos];
    cls = find_class(p, cls_name);
    if (!cls) {
        note("ommega-policy: 这份 policy 里没有类 %s，整条跳过", cls_name);
        return 0;
    }
    pos++;

    if (pos < ntok && strcmp(tok[pos], "*") == 0) {
        uint32_t count = class_perm_count(cls);

        mask = count >= 32 ? 0xffffffffu : ((1u << count) - 1u);
        pos++;
    } else {
        if (parse_nameset(tok, ntok, &pos, &perms) != 0) {
            note("ommega-policy: 权限那一段看不懂");
            return -1;
        }
        for (i = 0; i < perms.count; i++) {
            uint32_t bit = 0;

            if (perm_bit(p, cls, perms.name[i], &bit) != 0) {
                note("ommega-policy: 类 %s 没有权限 %s，跳过这一个", cls_name,
                     perms.name[i]);
                continue;
            }
            mask |= bit;
        }
        if (mask == 0)
            return 0;
    }

    for (i = 0; i < srcs.count; i++) {
        type_datum_t *src = find_type(p, srcs.name[i]);

        if (!src) {
            note("ommega-policy: 这份 policy 里没有类型 %s，跳过", srcs.name[i]);
            continue;
        }
        for (j = 0; j < tgts.count; j++) {
            type_datum_t *tgt;
            int rc;

            if (strcmp(tgts.name[j], "self") == 0)
                tgt = src;
            else
                tgt = find_type(p, tgts.name[j]);
            if (!tgt) {
                note("ommega-policy: 这份 policy 里没有类型 %s，跳过", tgts.name[j]);
                continue;
            }
            rc = add_allow(p, (uint16_t)src->s.value, (uint16_t)tgt->s.value,
                           (uint16_t)cls->s.value, mask);
            if (rc < 0) {
                note("ommega-policy: 插规则失败（%s %s:%s, errno=%d）",
                     srcs.name[i], tgts.name[j], cls_name, errno);
                return -1;
            }
            changed += rc;
        }
    }
    return changed;
}

static int apply_file(policydb_t *p, const char *path, int *seen, int *changed)
{
    FILE *f = fopen(path, "r");
    char line[MAX_LINE];
    int lineno = 0;

    if (!f) {
        note("ommega-policy: 打不开规则文件 %s：%s", path, strerror(errno));
        return -1;
    }
    while (fgets(line, sizeof(line), f)) {
        int rc;

        lineno++;
        rc = apply_statement(p, line);
        if (rc < 0) {
            note("ommega-policy: %s:%d 这一条没应用上", path, lineno);
            fclose(f);
            return -1;
        }
        (*seen)++;
        *changed += rc;
    }
    fclose(f);
    return 0;
}

/* ------------------------------------------------------------ 读写 policy */

static int load_policy(policydb_t *p, const char *path)
{
    char *data = NULL;
    size_t len = 0;
    policy_file_t pf;

    if (read_whole_file(path, &data, &len) != 0) {
        note("ommega-policy: 读不到 %s：%s", path, strerror(errno));
        return -1;
    }
    policy_file_init(&pf);
    pf.type = PF_USE_MEMORY;
    pf.data = data;
    pf.len = len;
    if (policydb_init(p) != 0) {
        note("ommega-policy: policydb_init 失败");
        free(data);
        return -1;
    }
    if (policydb_read(p, &pf, 0) != 0) {
        note("ommega-policy: %s 不是能解析的二进制 policy", path);
        policydb_destroy(p);
        free(data);
        return -1;
    }
    free(data);
    if (g_verbose)
        note("ommega-policy: 读到 policy %s（version=%u, 规则 %u 条）", path,
             p->policyvers, p->te_avtab.nel);
    return 0;
}

static int write_image(policydb_t *p, const char *path)
{
    void *image = NULL;
    size_t len = 0;
    int rc = -1;
    FILE *f;

    if (policydb_to_image(NULL, p, &image, &len) != 0 || !image) {
        note("ommega-policy: 生成 policy 镜像失败");
        return -1;
    }
    f = fopen(path, "wb");
    if (!f) {
        note("ommega-policy: 写不了 %s：%s", path, strerror(errno));
        free(image);
        return -1;
    }
    if (fwrite(image, 1, len, f) != len)
        note("ommega-policy: 写 %s 只写了一半：%s", path, strerror(errno));
    else
        rc = 0;
    fclose(f);
    free(image);
    return rc;
}

/* /sys/fs/selinux/load 只吃一次 write，分多次写会被拒（EINVAL）。 */
static int write_live(policydb_t *p)
{
    void *image = NULL;
    size_t len = 0;
    ssize_t written;
    int fd;

    if (policydb_to_image(NULL, p, &image, &len) != 0 || !image) {
        note("ommega-policy: 生成 policy 镜像失败");
        return -1;
    }
    fd = open(LIVE_LOAD, O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        note("ommega-policy: 打不开 %s：%s", LIVE_LOAD, strerror(errno));
        free(image);
        return -1;
    }
    written = write(fd, image, len);
    if (written != (ssize_t)len) {
        note("ommega-policy: 写 %s 失败：%s（写了 %zd/%zu）", LIVE_LOAD,
             written < 0 ? strerror(errno) : "short write", written, len);
        close(fd);
        free(image);
        return -1;
    }
    close(fd);
    free(image);
    if (g_verbose)
        note("ommega-policy: 已经把 %zu 字节塞进 %s", len, LIVE_LOAD);
    return 0;
}

/* ------------------------------------------------------------ 入口 */

static void usage(const char *prog)
{
    note("用法：%s [--live] [--apply FILE]... [--load FILE] [--save FILE] [--verbose] [规则...]",
         prog);
}

int main(int argc, char **argv)
{
    const char *in_path = LIVE_POLICY;
    const char *save_path = NULL;
    const char *apply_files[32];
    int apply_count = 0;
    const char *statements[64];
    int statement_count = 0;
    int live = 0;
    int check = 0;
    int i, seen = 0, changed = 0;
    policydb_t db;

    for (i = 1; i < argc; i++) {
        const char *arg = argv[i];

        if (strcmp(arg, "--live") == 0) {
            live = 1;
        } else if (strcmp(arg, "--check") == 0) {
            check = 1;
        } else if (strcmp(arg, "--verbose") == 0) {
            g_verbose = 1;
        } else if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
            usage(argv[0]);
            return 0;
        } else if (strcmp(arg, "--load") == 0 && i + 1 < argc) {
            in_path = argv[++i];
        } else if (strcmp(arg, "--save") == 0 && i + 1 < argc) {
            save_path = argv[++i];
        } else if (strcmp(arg, "--apply") == 0 && i + 1 < argc) {
            if (apply_count >= (int)(sizeof(apply_files) / sizeof(apply_files[0]))) {
                note("ommega-policy: --apply 太多了");
                return 2;
            }
            apply_files[apply_count++] = argv[++i];
        } else if (arg[0] == '-') {
            note("ommega-policy: 不认识的选项 %s", arg);
            usage(argv[0]);
            return 2;
        } else {
            if (statement_count >= (int)(sizeof(statements) / sizeof(statements[0]))) {
                note("ommega-policy: 规则太多了");
                return 2;
            }
            statements[statement_count++] = arg;
        }
    }

    if (!live && !save_path && !check && apply_count == 0 && statement_count == 0) {
        usage(argv[0]);
        return 2;
    }
    if (check && (live || save_path)) {
        note("ommega-policy: --check 不能跟 --live / --save 一起用");
        return 2;
    }

    if (load_policy(&db, in_path) != 0)
        return 1;

    for (i = 0; i < apply_count; i++) {
        if (apply_file(&db, apply_files[i], &seen, &changed) != 0) {
            policydb_destroy(&db);
            return 1;
        }
    }
    for (i = 0; i < statement_count; i++) {
        char *copy = strdup(statements[i]);
        int rc;

        if (!copy) {
            policydb_destroy(&db);
            return 1;
        }
        rc = apply_statement(&db, copy);
        free(copy);
        if (rc < 0) {
            policydb_destroy(&db);
            return 1;
        }
        seen++;
        changed += rc;
    }

    /* 这行不管开不开 verbose 都打：日志里得能看出「打了几条、动了几处」，
     * 否则没人能判断是规则全集上了、还是全被跳过了。 */
    note("ommega-policy: 规则 %d 条，动了 %d 处", seen, changed);

    if (save_path && write_image(&db, save_path) != 0) {
        policydb_destroy(&db);
        return 1;
    }
    if (live && write_live(&db) != 0) {
        policydb_destroy(&db);
        return 1;
    }
    if (check) {
        /* 规则全在 = 0；缺 = 3（调用方据此决定要不要真 apply）。 */
        policydb_destroy(&db);
        return changed > 0 ? 3 : 0;
    }
    policydb_destroy(&db);
    return 0;
}
