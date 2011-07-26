/* Copyright 2011 by Adrian Schroeter <adrian@suse.de>
 * based on mod_xsendfile: Copyright 2006 by Nils Maier
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * mod_xforward.c: Backend process may set X-FORWARD header
 *
 * Whenever an X-FORWARD header occures in the response headers drop
 * the body and do an internal redirect to the specified URL via mod_proxy
 * module.
 *
 * There is no need to configure a proxy in apache config, we always
 * trust our backend to send valid redirections.
 *
 * Method inspired by lighttpd <http://lighttpd.net/>
 * Code inspired by mod_headers, mod_rewrite and such
 *
 * Configuration:
 *   You may turn on processing in any context, where perdir config overrides server config:
 *   XForward On|Off - Enable/disable(default) processing
 *
 * Installation:
 *     apxs2 -cia mod_xforward.c
 */


#include "apr.h"
#include "apr_lib.h"
#include "apr_strings.h"
#include "apr_buckets.h"
#include "apr_file_io.h"

#include "apr_hash.h"
#define APR_WANT_IOVEC
#define APR_WANT_STRFUNC
#include "apr_want.h"

#include "httpd.h"
#include "http_log.h"
#include "http_config.h"
#include "http_log.h"
#define CORE_PRIVATE
#include "http_request.h"
#include "http_core.h" /* needed for per-directory core-config */
#include "util_filter.h"
#include "http_protocol.h" /* ap_hook_insert_error_filter */

#define AP_XFORWARD_HEADER "X-FORWARD"

#if defined(__GNUC__) && (__GNUC__ > 2)
#   define AP_XFORWARD_EXPECT_TRUE(x) __builtin_expect((x), 1);
#   define AP_XFORWARD_EXPECT_FALSE(x) __builtin_expect((x), 0);
#else
#   define AP_XFORWARD_EXPECT_TRUE(x) (x)
#   define AP_XFORWARD_EXPECT_FALSE(x) (x)
#endif

#define _DEBUG 1

module AP_MODULE_DECLARE_DATA xforward_module;

typedef enum {
    XFORWARD_UNSET, XFORWARD_ENABLED, XFORWARD_DISABLED
} xforward_conf_active_t;

typedef struct xforward_conf_t
{
    xforward_conf_active_t enabled;
} xforward_conf_t;

static void *xforward_config_server_create(apr_pool_t *p, server_rec *s)
{
    xforward_conf_t *conf;

    conf = (xforward_conf_t *) apr_pcalloc(p, sizeof(xforward_conf_t));
    conf->enabled = XFORWARD_UNSET;

    return (void*)conf;
}

#define XFORWARD_CFLAG(x) conf->x = overrides->x != XFORWARD_UNSET ? overrides->x : base->x

static void *xforward_config_server_merge(apr_pool_t *p, void *basev, void *overridesv)
{
    xforward_conf_t *base = (xforward_conf_t *) basev;
    xforward_conf_t *overrides = (xforward_conf_t *) overridesv;
    xforward_conf_t *conf;

    conf = (xforward_conf_t *) apr_pcalloc(p, sizeof(xforward_conf_t));

    XFORWARD_CFLAG(enabled);

    return (void*)conf;
}

static void *xforward_config_perdir_create(apr_pool_t *p, char *path)
{
    xforward_conf_t *conf;

    conf = (xforward_conf_t *)apr_pcalloc(p, sizeof(xforward_conf_t));
    conf->enabled = XFORWARD_UNSET;

    return (void*)conf;
}

static void *xforward_config_perdir_merge(apr_pool_t *p, void *basev, void *overridesv)
{
    xforward_conf_t *base = (xforward_conf_t *) basev;
    xforward_conf_t *overrides = (xforward_conf_t*)overridesv;
    xforward_conf_t *conf;

    conf = (xforward_conf_t*)apr_pcalloc(p, sizeof(xforward_conf_t));


    XFORWARD_CFLAG(enabled);
    
    return (void*)conf;
}
#undef XFORWARD_CFLAG

static const char *xforward_cmd_flag(cmd_parms *cmd, void *perdir_confv, int flag)
{
    xforward_conf_t *conf = (xforward_conf_t *)perdir_confv;
    if (cmd->path == NULL)
    {
        conf = (xforward_conf_t*)ap_get_module_config(
            cmd->server->module_config,
            &xforward_module
            );
    }
    if (conf)
    {
        if (strcasecmp(cmd->cmd->name, "xforward") == 0)
        {
            conf->enabled = flag ? XFORWARD_ENABLED : XFORWARD_DISABLED;
        }
    }
    return NULL;
}

static apr_status_t ap_xforward_output_filter(
    ap_filter_t *f,
    apr_bucket_brigade *in
)
{
    request_rec *r = f->r;

    apr_bucket *e;

    const char *url = NULL;

#ifdef _DEBUG
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "xforward: output_filter for %s", r->the_request);
#endif

    /*
        should we proceed with this request?

        * sub-requests suck
        * furthermore default-handled requests suck, as they actually shouldn't be able to set headers
    */
    if (
        r->status != HTTP_OK
        || r->main
        || (r->handler && strcmp(r->handler, "default-handler") == 0) /* those table-keys are lower-case, right? */
    )
    {
#ifdef _DEBUG
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "xforward: not met [%d]", r->status);
#endif
        ap_remove_output_filter(f);
        return ap_pass_brigade(f->next, in);
    }

    /*
        alright, look for x-forwward
    */
    url = apr_table_get(r->headers_out, AP_XFORWARD_HEADER);
    if (url) {
	url = apr_pstrdup(r->pool, url);
	apr_table_unset(r->headers_out, AP_XFORWARD_HEADER);
    }

    /* cgi/fastcgi will put the stuff into err_headers_out */
    if (!url || !*url)
    {
        url = apr_table_get(r->err_headers_out, AP_XFORWARD_HEADER);
	if (url) {
	    url = apr_pstrdup(r->pool, url);
	    apr_table_unset(r->err_headers_out, AP_XFORWARD_HEADER);
	}
    }

    /* nothing there :p */
    if (!url || !*url)
    {
#ifdef _DEBUG
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "xforward: nothing found");
#endif
        ap_remove_output_filter(f);
        return ap_pass_brigade(f->next, in);
    }

    if (ap_find_linked_module("mod_proxy.c") == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ALERT, 0, r->server, "xforward: mod_proxy.c is not available");
        ap_remove_output_filter(f);
        return ap_pass_brigade(f->next, in);
    }

    /*
        drop *everything*
        might be pretty expensive to generate content first that goes straight to the bitbucket,
        but actually the scripts that might set this flag won't output too much anyway
    */
    while (!APR_BRIGADE_EMPTY(in))
    {
        e = APR_BRIGADE_FIRST(in);
        apr_bucket_delete(e);
    }
    r->eos_sent = 0;

#ifdef _DEBUG
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "xforward: url is %s", url);
#endif

    /*
        let apache do an internal redirect
    */

    /* now make sure the request gets handled by the proxy handler */
    if (PROXYREQ_NONE == r->proxyreq) {
        r->proxyreq = PROXYREQ_REVERSE;
    }
    r->filename = apr_pstrcat(r->pool, "proxy:", url, NULL);
    r->handler  = "proxy-server";

    /* make proxy url available to the fixup */
    apr_pool_userdata_setn(r->filename, "XFORWARD_REDIRECT_URL", NULL, r->pool);

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "xforward: redirect to %s", r->filename);

    /* hand over to mod_proxy module */
    ap_internal_redirect_handler(url, r);

    return OK;
}

static void ap_xforward_insert_output_filter(request_rec *r)
{
    xforward_conf_active_t enabled = ((xforward_conf_t *)ap_get_module_config(r->per_dir_config, &xforward_module))->enabled;
    if (XFORWARD_UNSET == enabled)
    {
        enabled = ((xforward_conf_t*)ap_get_module_config(r->server->module_config, &xforward_module))->enabled;
    }

    if (XFORWARD_ENABLED != enabled)
    {
        return;
    }

    ap_add_output_filter(
        "XFORWARD",
        NULL,
        r,
        r->connection
    );
}
static const command_rec xforward_command_table[] = {
    AP_INIT_FLAG(
        "XForward",
        xforward_cmd_flag,
        NULL,
        OR_OPTIONS,
        "On|Off - Enable/disable(default) processing"
        ),
    { NULL }
};

static int hook_fixup(request_rec *r)
{
    const char *url = NULL;
    if (!r->prev)
	return DECLINED;	/* not redirected */
    if (apr_pool_userdata_get((void **)&url, "XFORWARD_REDIRECT_URL", r->prev->pool) != APR_SUCCESS || url == NULL)
	return DECLINED;	/* not redireced by us */
    
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "xforward: FIXUP OK %s", url );
    r->filename = apr_pstrdup(r->pool, url);
    r->handler  = "proxy-server";
    if (PROXYREQ_NONE == r->proxyreq) {
	r->proxyreq = PROXYREQ_REVERSE;
    }
    return OK;
}

static void xforward_register_hooks(apr_pool_t *p)
{
    static const char * const aszPre[]={ "mod_proxy.c", NULL };
    ap_hook_fixups(hook_fixup, aszPre, NULL, APR_HOOK_FIRST);

    ap_register_output_filter(
        "XFORWARD",
        ap_xforward_output_filter,
        NULL,
        AP_FTYPE_CONTENT_SET
        );

    ap_hook_insert_filter(
        ap_xforward_insert_output_filter,
        NULL,
        NULL,
        APR_HOOK_LAST + 1
        );
}
module AP_MODULE_DECLARE_DATA xforward_module =
{
    STANDARD20_MODULE_STUFF,
    xforward_config_perdir_create,
    xforward_config_perdir_merge,
    xforward_config_server_create,
    xforward_config_server_merge,
    xforward_command_table,
    xforward_register_hooks
};
