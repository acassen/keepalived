/*
 * Soft:	Keepalived is a failover program for the LVS project
 *		<www.linuxvirtualserver.org>. It monitor & manipulate
 *		a loadbalanced server pool using multi-layer checks.
 *
 * Part:	rbtree_ka.h include file.
 *
 * Author:	Alexandre Cassen, <acassen@linux-vs.org>
 *
 *		This program is distributed in the hope that it will be useful,
 *		but WITHOUT ANY WARRANTY; without even the implied warranty of
 *		MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *		See the GNU General Public License for more details.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Copyright (C) 2021-2021 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _RBTREE_KA_H
#define _RBTREE_KA_H

#include "rbtree.h"

typedef struct rb_node rb_node_t;
typedef struct rb_root rb_root_t;
typedef struct rb_root_cached rb_root_cached_t;


/**
 * rb_for_each_entry -  Iterate over rbtree of given type
 * @pos:		the type * to use as a loop cursor.
 * @root:		the rbtree root.
 * @member:		the name of the rb_node within the struct.
 */
#define rb_for_each_entry(pos, root, member)				\
	for (pos = rb_entry_safe(rb_first(root), typeof(*pos), member);	\
	     pos; pos = rb_entry_safe(rb_next(&pos->member), typeof(*pos), member))
#define rb_for_each_entry_const(pos, root, member)				\
	for (pos = rb_entry_safe_const(rb_first(root), typeof(*pos), member);	\
	     pos; pos = rb_entry_safe_const(rb_next(&pos->member), typeof(*pos), member))

/**
 * rb_for_each_entry_safe -	Iterate over rbtree of given type safe against removal
 * @pos:			the type * to use as a loop cursor.
 * @root:			the rbtree root.
 * @member:			the name of the rb_node within the struct.
 */
#define rb_for_each_entry_safe(pos, n, root, member)					\
	for (pos = rb_entry_safe(rb_first(root), typeof(*pos), member);			\
	     pos && (n = rb_entry_safe(rb_next(&pos->member), typeof(*n), member), 1);	\
	     pos = n)

/**
 * rb_for_each_entry_cached -  Iterate over cached rbtree of given type
 * @pos:                the type * to use as a loop cursor.
 * @root:               the rbtree root.
 * @member:             the name of the rb_node within the struct.
 */
#define rb_for_each_entry_cached(pos, root, member)				\
	for (pos = rb_entry_safe(rb_first_cached(root), typeof(*pos), member);	\
	     pos; pos = rb_entry_safe(rb_next(&pos->member), typeof(*pos), member))
#define rb_for_each_entry_cached_const(pos, root, member)				\
	for (pos = rb_entry_safe_const(rb_first_cached(root), typeof(*pos), member);	\
	     pos; pos = rb_entry_safe_const(rb_next(&pos->member), typeof(*pos), member))

/**
 * rb_for_each_entry_safe_cached - Iterate over cached rbtree of given type
 * @pos:                the type * to use as a loop cursor.
 * @root:               the rbtree root.
 * @member:             the name of the rb_node within the struct.
 */
#define rb_for_each_entry_safe_cached(pos, n, root, member)				\
	for (pos = rb_entry_safe(rb_first_cached(root), typeof(*pos), member);		\
	     pos && (n = rb_entry_safe(rb_next(&pos->member), typeof(*n), member), 1);	\
	     pos = n)

/**
 * rb_move_cached -	Move node to new position in tree
 * @node:		the node to move.
 * @root:		the rbtree root.
 * @less:		the name of the less function to use.
 */
static __always_inline void
rb_move_cached(struct rb_node *node, struct rb_root_cached *tree,
	       bool (*less)(struct rb_node *, const struct rb_node *))
{
	rb_node_t *prev_node, *next_node;

	prev_node = rb_prev(node);
	next_node = rb_next(node);

	if (prev_node || next_node) {
		/* If node is between our predecessor and successor,
		 * it can stay where it is */
		if ((prev_node && less(node, prev_node)) ||
		    (next_node && less(next_node, node))) {
			/* Can this be optimised? */
			rb_erase_cached(node, tree);
			rb_add_cached(node, tree, less);
		}
	}
}

#endif	/* _LINUX_RBTREE_H */
