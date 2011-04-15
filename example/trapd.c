#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/library/snmp_transport.h>

#define MAX_TYPE_NAME_LEN 32
#define STR_BUF_SIZE (MAX_TYPE_NAME_LEN * MAX_OID_LEN)

static char *program_name;

static int pre_parse(netsnmp_session * session, netsnmp_transport *transport, void *transport_data, int transport_data_length) {
  char hostname[NI_MAXHOST];
  getnameinfo((struct sockaddr*) transport_data, INET_ADDRSTRLEN, hostname, NI_MAXHOST, NULL, 0, 0);
  printf("%s: pre_parse: hostname=%s\n", program_name, hostname);
}

static int snmp_input(int op, netsnmp_session *session, int reqid, netsnmp_pdu *pdu, void *magic) {
  netsnmp_variable_list *var;
  char str_buf[STR_BUF_SIZE];
  for(var=pdu->variables; var; var=var->next_variable) {
    if (var->type == ASN_OBJECT_ID) {
      snprint_objid(str_buf, sizeof(str_buf), var->val.objid, var->val_len/sizeof(oid));
      printf("%s: snmp_input: oid=%s\n", program_name, str_buf);
    }
  }
  return 0;
}

static netsnmp_session *snmptrapd_add_session(netsnmp_transport *t) {
    netsnmp_session sess, *session = &sess, *rc = NULL;
    snmp_sess_init(session);
    session->peername = SNMP_DEFAULT_PEERNAME;  /* Original code had NULL here */
    session->version = SNMP_DEFAULT_VERSION;
    session->community_len = SNMP_DEFAULT_COMMUNITY_LEN;
    session->retries = SNMP_DEFAULT_RETRIES;
    session->timeout = SNMP_DEFAULT_TIMEOUT;
    session->callback = snmp_input;
    session->callback_magic = (void *) t;
    session->authenticator = NULL;
    sess.isAuthoritative = SNMP_SESS_UNKNOWNAUTH;
    rc = snmp_add(session, t, pre_parse, NULL);
    if (rc == NULL) {
        snmp_sess_perror("snmptrapd", session);
    }
    return rc;
}

static void select_loop() {
  int count, numfds, block;
  fd_set readfds, writefds, exceptfds;
  struct timeval timeout, *tvp;
  while (1) {
    numfds = 0;
    FD_ZERO(&readfds);
    FD_ZERO(&writefds);
    FD_ZERO(&exceptfds);
    block = 0;
    tvp = &timeout;
    timerclear(tvp);
    tvp->tv_sec = 5;
    snmp_select_info(&numfds, &readfds, tvp, &block);
    if (block == 1) {
      tvp = NULL;
    }
    count = select(numfds, &readfds, &writefds, &exceptfds, tvp);
    printf("%s: select returned %d\n", program_name, count);
    if (count > 0) {
      snmp_read(&readfds);
    } else {
      switch (count) {
      case 0:
        snmp_timeout();
        break;
      case -1:
        if (errno == EINTR) {
          continue;
        }
        snmp_log_perror("select");
        break;
      }
    }
  }
}

int main(int argc, char **argv) {
  netsnmp_session *session = NULL;
  netsnmp_transport *transport = NULL;
  char *listening_address = "udp:5200";
  int local = 1;
  char *default_domain = "udp";
  program_name = basename(argv[0]);
  printf("%s: main\n", program_name);
  init_usm();
  netsnmp_udp_ctor();
  netsnmp_udpipv6_ctor();
  init_snmpv3(NULL);
  setup_engineID(NULL, NULL);
  usm_parse_create_usmUser("createUser", "-e 0x8000000001020304 traptest SHA mypassword AES");
  transport = netsnmp_tdomain_transport(listening_address, local, default_domain);
  if (transport == NULL) {
    printf("%s: failed to open server: %s\n", argv[0], strerror(errno));
    exit(EXIT_FAILURE);
  }
  session = snmptrapd_add_session(transport);
  select_loop();
  snmp_close(session);
  exit(EXIT_SUCCESS);
}
