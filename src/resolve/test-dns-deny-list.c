/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>

#include "dns-domain.h"
#include "dns-rr.h"
#include "resolved-dns-query.h"
#include "resolved-manager.h"
#include "set.h"
#include "string-util.h"
#include "tests.h"

static Manager *test_manager_new_with(const char *pattern) {
        _cleanup_free_ char *normalized = NULL;
        bool subdomains_only = false;
        const char *name = pattern;
        Manager *m;
        int r;

        m = new0(Manager, 1);
        ASSERT_NOT_NULL(m);

        m->dns_deny_list_enabled = true;

        m->dns_deny_list = set_new(&dns_name_hash_ops_free);
        ASSERT_NOT_NULL(m->dns_deny_list);

        m->dns_deny_list_subdomains_only = set_new(&dns_name_hash_ops_free);
        ASSERT_NOT_NULL(m->dns_deny_list_subdomains_only);

        if (startswith(pattern, "*.")) {
                subdomains_only = true;
                name += 2;
        }

        r = dns_name_normalize(name, 0, &normalized);
        ASSERT_OK(r);

        if (subdomains_only)
                ASSERT_OK(set_ensure_consume(&m->dns_deny_list_subdomains_only, &dns_name_hash_ops_free, TAKE_PTR(normalized)));
        else
                ASSERT_OK(set_ensure_consume(&m->dns_deny_list, &dns_name_hash_ops_free, TAKE_PTR(normalized)));

        return m;
}

static Manager *test_manager_free(Manager *m) {
        if (!m)
                return NULL;
        m->dns_deny_list = set_free(m->dns_deny_list);
        m->dns_deny_list_subdomains_only = set_free(m->dns_deny_list_subdomains_only);
        return mfree(m);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, test_manager_free);

static void test_match_cname(const char *entry, const char *rr_name, bool expected) {
        _cleanup_(test_manager_freep) Manager *m = test_manager_new_with(entry);
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_CNAME, "www.example.com");
        ASSERT_NOT_NULL(rr);
        rr->ptr.name = strdup(rr_name);
        ASSERT_NOT_NULL(rr->ptr.name);

        ASSERT_EQ(manager_find_deny_list_match_rr(m, rr) != NULL, expected);
}

static void test_match_a(const char *entry, const char *rr_name, bool expected) {
        _cleanup_(test_manager_freep) Manager *m = test_manager_new_with(entry);
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, rr_name);
        ASSERT_NOT_NULL(rr);
        rr->a.in_addr.s_addr = htobe32(0x01020304);

        ASSERT_EQ(manager_find_deny_list_match_rr(m, rr) != NULL, expected);
}

static void test_match_aaaa(const char *entry, const char *rr_name, bool expected) {
        _cleanup_(test_manager_freep) Manager *m = test_manager_new_with(entry);
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_AAAA, rr_name);
        ASSERT_NOT_NULL(rr);

        ASSERT_EQ(manager_find_deny_list_match_rr(m, rr) != NULL, expected);
}

static void test_match_mx(const char *entry, const char *rr_name, bool expected) {
        _cleanup_(test_manager_freep) Manager *m = test_manager_new_with(entry);
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_MX, "example.com");
        ASSERT_NOT_NULL(rr);
        rr->mx.exchange = strdup(rr_name);
        rr->mx.priority = 10;
        ASSERT_NOT_NULL(rr->mx.exchange);

        ASSERT_EQ(manager_find_deny_list_match_rr(m, rr) != NULL, expected);
}

static void test_match_ns(const char *entry, const char *rr_name, bool expected) {
        _cleanup_(test_manager_freep) Manager *m = test_manager_new_with(entry);
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_NS, "example.com");
        ASSERT_NOT_NULL(rr);
        rr->ns.name = strdup(rr_name);
        ASSERT_NOT_NULL(rr->ns.name);

        ASSERT_EQ(manager_find_deny_list_match_rr(m, rr) != NULL, expected);
}

static void test_match_soa(const char *entry, const char *mname, const char *rname, bool expected) {
        _cleanup_(test_manager_freep) Manager *m = test_manager_new_with(entry);
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_SOA, "example.com");
        ASSERT_NOT_NULL(rr);
        rr->soa.mname = strdup(mname);
        ASSERT_NOT_NULL(rr->soa.mname);
        rr->soa.rname = strdup(rname);
        ASSERT_NOT_NULL(rr->soa.rname);

        ASSERT_EQ(manager_find_deny_list_match_rr(m, rr) != NULL, expected);
}

static void test_match_dname(const char *entry, const char *target, bool expected) {
        _cleanup_(test_manager_freep) Manager *m = test_manager_new_with(entry);
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_DNAME, "example.com");
        ASSERT_NOT_NULL(rr);
        rr->dname.name = strdup(target);
        ASSERT_NOT_NULL(rr->dname.name);

        ASSERT_EQ(manager_find_deny_list_match_rr(m, rr) != NULL, expected);
}

static void test_match_naptr(const char *entry, const char *replacement, bool expected) {
        _cleanup_(test_manager_freep) Manager *m = test_manager_new_with(entry);
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_NAPTR, "example.com");
        ASSERT_NOT_NULL(rr);
        rr->naptr.flags = strdup("U");
        ASSERT_NOT_NULL(rr->naptr.flags);
        rr->naptr.services = strdup("E2U+sip");
        ASSERT_NOT_NULL(rr->naptr.services);
        rr->naptr.regexp = strdup("!^.*$!sip:customer-service@example.com!");
        ASSERT_NOT_NULL(rr->naptr.regexp);
        rr->naptr.replacement = strdup(replacement);
        ASSERT_NOT_NULL(rr->naptr.replacement);

        ASSERT_EQ(manager_find_deny_list_match_rr(m, rr) != NULL, expected);
}

static void test_match_svcb(const char *entry, uint16_t type, const char *target, bool expected) {
        _cleanup_(test_manager_freep) Manager *m = test_manager_new_with(entry);
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        rr = dns_resource_record_new_full(DNS_CLASS_IN, type, "_443._wss.example.com");
        ASSERT_NOT_NULL(rr);
        rr->svcb.target_name = strdup(target);
        ASSERT_NOT_NULL(rr->svcb.target_name);

        ASSERT_EQ(manager_find_deny_list_match_rr(m, rr) != NULL, expected);
}

TEST(dns_deny_list_basic_domain) {
        test_match_a("google.com", "google.com", true);
        test_match_a("google.com", "www.google.com", true);
        test_match_a("example.com", "example.com", true);
        test_match_a("example.com", "other.com", false);
}

TEST(dns_deny_list_subdomain) {
        test_match_a("*.ads.example.com", "ads.example.com", false);
        test_match_a("*.ads.example.com", "www.ads.example.com", true);
        test_match_a("*.example.com", "ads.example.com", true);
}

TEST(dns_deny_list_cname) {
        test_match_cname("ads.example.com", "ads.example.com", true);
        test_match_cname("ads.example.com", "www.ads.example.com", true);
        test_match_cname("example.com", "ads.example.com", true);
        test_match_cname("ads.example.com", "benign.com", false);
}

TEST(dns_deny_list_mx) {
        test_match_mx("mail.ads.example.com", "mail.ads.example.com", true);
        test_match_mx("ads.example.com", "mail.ads.example.com", true);
        test_match_mx("example.com", "mail.ads.example.com", true);
        test_match_mx("mail.example.com", "mail.ads.example.com", false);
}

TEST(dns_deny_list_ns) {
        test_match_ns("ns1.ads.example.com", "ns1.ads.example.com", true);
        test_match_ns("ads.example.com", "ns1.ads.example.com", true);
        test_match_ns("example.com", "ns1.ads.example.com", true);
        test_match_ns("ns1.example.com", "ns1.ads.example.com", false);
}

TEST(dns_deny_list_aaaa) {
        test_match_aaaa("google.com", "google.com", true);
        test_match_aaaa("google.com", "www.google.com", true);
}

TEST(dns_deny_list_wildcard_tld) {
        test_match_a("com", "google.com", true);
        test_match_a("com", "example.org", false);
        test_match_a("net", "google.net", true);
        test_match_a("org", "example.org", true);
}

TEST(dns_deny_list_complex_subdomain) {
        test_match_a("tracker.example.com", "cdn.tracker.example.com", true);
        test_match_a("tracker.example.com", "tracker.example.com", true);
        test_match_a("example.com", "cdn.tracker.example.com", true);
        test_match_a("example.com", "cdn.example.com", true);
        test_match_a("example.org", "cdn.tracker.example.com", false);
}

TEST(dns_deny_list_dname_naptr_svcb_https_and_soa_rname) {
        test_match_dname("v2.example.com", "v2.example.com", true);
        test_match_dname("v2.example.com", "v3.example.com", false);

        test_match_naptr("_sip._udp.example.com", "_sip._udp.example.com", true);
        test_match_naptr("_sip._udp.example.com", "_sip._udp.other.com", false);

        test_match_svcb("sock.example.com", DNS_TYPE_SVCB, "sock.example.com", true);
        test_match_svcb("sock.example.com", DNS_TYPE_SVCB, "other.example.com", false);

        test_match_svcb("sock.example.com", DNS_TYPE_HTTPS, "sock.example.com", true);
        test_match_svcb("sock.example.com", DNS_TYPE_HTTPS, "other.example.com", false);

        test_match_soa("admin.example.com", "ns.example.com", "admin.example.com", true);
        test_match_soa("admin.example.com", "ns.example.com", "other.example.com", false);
}

static int intro(void) {
        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
