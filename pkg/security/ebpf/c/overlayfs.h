#ifndef _OVERLAYFS_H_
#define _OVERLAYFS_H_

#include "syscalls.h"

#define OVERLAYFS_SUPER_MAGIC 0x794c7630

int __attribute__((always_inline)) get_sizeof_inode() {
    u64 sizeof_inode;
    LOAD_CONSTANT("sizeof_inode", sizeof_inode);

    return sizeof_inode;
}

int __attribute__((always_inline)) get_sb_magic_offset() {
    u64 offset;
    LOAD_CONSTANT("sb_magic_offset", offset);

    return offset;
}

static __attribute__((always_inline)) int is_overlayfs(struct dentry *dentry) {
    struct inode *d_inode;
    bpf_probe_read(&d_inode, sizeof(d_inode), &dentry->d_inode);

    struct super_block *sb;
    bpf_probe_read(&sb, sizeof(sb), &d_inode->i_sb);

    u64 magic;
    bpf_probe_read(&magic, sizeof(magic), (char *)sb + get_sb_magic_offset());

    return magic == OVERLAYFS_SUPER_MAGIC;
}

int __attribute__((always_inline)) get_ovl_lower_ino(struct dentry *dentry) {
    struct inode *d_inode;
    bpf_probe_read(&d_inode, sizeof(d_inode), &dentry->d_inode);

    // escape from the embedded vfs_inode to reach ovl_inode
    struct inode *lower;
    bpf_probe_read(&lower, sizeof(lower), (char *)d_inode + get_sizeof_inode() + 8);

    return get_inode_ino(lower);
}

int __attribute__((always_inline)) get_ovl_upper_ino(struct dentry *dentry) {
    struct inode *d_inode;
    bpf_probe_read(&d_inode, sizeof(d_inode), &dentry->d_inode);

    // escape from the embedded vfs_inode to reach ovl_inode
    struct dentry *upper;
    bpf_probe_read(&upper, sizeof(upper), (char *)d_inode + get_sizeof_inode());

    return get_dentry_ino(upper);
}

int __always_inline get_overlayfs_ino(struct dentry *dentry, struct path_key_t *path_key) {
    u64 lower_inode = get_ovl_lower_ino(dentry);
    u64 upper_inode = get_ovl_upper_ino(dentry);

    bpf_printk("get_overlayfs_ino inode: %d %d\n", lower_inode, upper_inode);

    if (lower_inode) {
        return lower_inode;
    } else if (upper_inode) {
        return upper_inode;
    }
    return path_key->ino;
}

#endif