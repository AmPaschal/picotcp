DEBUG_ALL?=1

DEBUG_ARP?=0
DEBUG_AODV?=0
DEBUG_PPP?=0
DEBUG_TAP_ALL?=0
DEBUG_TAP_GENERAL?=0
DEBUG_TAP_INFO?=0
DEBUG_TAP_WIN?=0
DEBUG_TAP_REG?=0
DEBUG_DHCP_CLIENT?=0
DEBUG_DHCP_SERVER?=0
DEBUG_DNS?=0
DEBUG_DNS_SD?=0
DEBUG_FRAG?=0
DEBUG_IGMP?=0
DEBUG_IPF?=0
DEBUG_MCAST?=0
DEBUG_IPV6?=0
DEBUG_IPV6_ROUTE?=0
DEBUG_IPV6_ND?=0
DEBUG_MDNS?=0
DEBUG_MLD?=0
DEBUG_MM?=0
DEBUG_NAT?=0
DEBUG_OLSR?=0
DEBUG_SLAACV4?=0
DEBUG_SNTP?=0
DEBUG_TCP_ALL?=0
DEBUG_TCP_NAGLE?=0
DEBUG_TCP_OPTIONS?=0
DEBUG_TCP_GENERAL?=0
DEBUG_TFTP?=0
DEBUG_UDP?=0
DEBUG_6LOWPAN?=0
DEBUG_RADIOTEST?=0

ifneq ($(DEBUG_ALL),0)
	DEBUG_ARP=1
	DEBUG_AODV=1
	DEBUG_PPP=1
	DEBUG_TAP_ALL=1
	DEBUG_DHCP_CLIENT=1
	DEBUG_DHCP_SERVER=1
	DEBUG_DNS=1
	DEBUG_DNS_SD=1
	DEBUG_FRAG=1
	DEBUG_ICMP6=1
	DEBUG_IGMP=1
	DEBUG_IPF=1
	DEBUG_MCAST=1
	DEBUG_IPV6=1
	DEBUG_IPV6_ROUTE=1
	DEBUG_IPV6_ND=1
	DEBUG_MDNS=1
	DEBUG_MLD=1
	DEBUG_MM=1
	DEBUG_NAT=1
	DEBUG_OLSR=1
	DEBUG_SLAACV4=1
	DEBUG_SNTP=1
	DEBUG_TCP_ALL=1
	DEBUG_TFTP=1
	DEBUG_UDP=1
	DEBUG_6LOWPAN=1
	DEBUG_RADIOTEST=1
endif

ifneq ($(DEBUG_TCP_ALL),0)
	DEBUG_TCP_NAGLE=1
	DEBUG_TCP_OPTIONS=1
	DEBUG_TCP_GENERAL=1
endif

ifneq ($(DEBUG_TAP_ALL),0)
	DEBUG_TAP_GENERAL=1
	DEBUG_TAP_INFO=1
	DEBUG_TAP_WIN=1
	DEBUG_TAP_REG=1
endif

ifneq ($(DEBUG_ARP),0)
	CFLAGS+=-DDEBUG_ARP
endif

ifneq ($(DEBUG_AODV),0)
	CFLAGS+=-DDEBUG_AODV
endif

ifneq ($(DEBUG_PPP),0)
	CFLAGS+=-DDEBUG_PPP
endif

ifneq ($(DEBUG_TAP_GENERAL),0)
	CFLAGS+=-DDEBUG_TAP_GENERAL
endif

ifneq ($(DEBUG_TAP_INFO),0)
	CFLAGS+=-DDEBUG_TAP_INFO
endif

ifneq ($(DEBUG_TAP_WIN),0)
	CFLAGS+=-DDEBUG_TAP_WIN
endif

ifneq ($(DEBUG_TAP_REG),0)
	CFLAGS+=-DDEBUG_TAP_REG
endif

ifneq ($(DEBUG_DHCP_CLIENT),0)
	CFLAGS+=-DDEBUG_DHCP_CLIENT
endif

ifneq ($(DEBUG_DHCP_SERVER),0)
	CFLAGS+=-DDEBUG_DHCP_SERVER
endif

ifneq ($(DEBUG_DNS),0)
	CFLAGS+=-DDEBUG_DNS
endif

ifneq ($(DEBUG_DNS_SD),0)
	CFLAGS+=-DDEBUG_DNS_SD
endif

ifneq ($(DEBUG_FRAG),0)
	CFLAGS+=-DDEBUG_FRAG
endif

ifneq ($(DEBUG_IGMP),0)
	CFLAGS+=-DDEBUG_IGMP
endif

ifneq ($(DEBUG_IPF),0)
	CFLAGS+=-DDEBUG_IPF
endif

ifneq ($(DEBUG_MCAST),0)
	CFLAGS+=-DDEBUG_MCAST
endif

ifneq ($(DEBUG_IPV6),0)
	CFLAGS+=-DDEBUG_IPV6
endif

ifneq ($(DEBUG_IPV6_ROUTE),0)
	CFLAGS+=-DDEBUG_IPV6_ROUTE
endif

ifneq ($(DEBUG_IPV6_ND),0)
	CFLAGS+=-DDEBUG_IPV6_ND
endif

ifneq ($(DEBUG_MDNS),0)
	CFLAGS+=-DDEBUG_MDNS
endif

ifneq ($(DEBUG_MLD),0)
	CFLAGS+=-DDEBUG_MLD
endif

ifneq ($(DEBUG_MM),0)
	CFLAGS+=-DDEBUG_MM
endif

ifneq ($(DEBUG_NAT),0)
	CFLAGS+=-DDEBUG_NAT
endif

ifneq ($(DEBUG_OLSR),0)
	CFLAGS+=-DDEBUG_OLSR
endif

ifneq ($(DEBUG_SLAACV4),0)
	CFLAGS+=-DDEBUG_SLAACV4
endif

ifneq ($(DEBUG_SNTP),0)
	CFLAGS+=-DDEBUG_SNTP
endif

ifneq ($(DEBUG_TCP_NAGLE),0)
	CFLAGS+=-DDEBUG_TCP_NAGLE
endif

ifneq ($(DEBUG_TCP_OPTIONS),0)
	CFLAGS+=-DDEBUG_TCP_OPTIONS
endif

ifneq ($(DEBUG_TCP_GENERAL),0)
	CFLAGS+=-DDEBUG_TCP_GENERAL
endif

ifneq ($(DEBUG_TFTP),0)
	CFLAGS+=-DDEBUG_TFTP
endif

ifneq ($(DEBUG_UDP),0)
	CFLAGS+=-DDEBUG_UDP
endif

ifneq ($(DEBUG_6LOWPAN),0)
	CFLAGS+=-DDEBUG_6LOWPAN
endif

ifneq ($(DEBUG_RADIOTEST), 0)
	CFLAGS+=-DDEBUG_RADIOTEST
endif
