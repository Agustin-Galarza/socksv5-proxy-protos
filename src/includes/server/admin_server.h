#ifndef ADMINSV_H_
#define ADMINSV_H_

#include "utils/netutils.h"
#include "utils/selector.h"
#include "utils/user_list.h"

#define ADMIN_SERVER_VERSION 0x01

bool admin_server_init(user_list_t* initial_users);

void admin_server_close();

const struct fd_handler* get_admin_server_handlers();

user_list_t* admin_server_get_allowed_users();

extern struct admin_server_data admin_server_data;

#endif
