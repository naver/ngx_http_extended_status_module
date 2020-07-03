
#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <ctype.h>
#include <assert.h>

#include "ngx_http_extended_status_module.h"

extern  ngx_uint_t  ngx_num_workers;

static char  * ngx_http_set_status( ngx_conf_t *cf, ngx_command_t *cmd, void *conf ) ;

static ngx_command_t  ngx_http_status_commands[] = {

    { ngx_string("extended_status"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_http_set_status,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_extended_status_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_extended_status_module = {
    NGX_MODULE_V1,
    &ngx_http_extended_status_module_ctx,      /* module context */
    ngx_http_status_commands,              /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static int
n_digit( uint64_t  num )
{
    int  ndigit = 0 ;

    if ( 0 == num )
        return 1 ;

    while ( 0 < num )
    {
        num = num / 10 ;
        ndigit += 1 ;
    }

    return ndigit ;
}


static int
to_string( uint64_t  num, unsigned int  len, char  * buf )
{
    int  ndigit = 0 ;
    int  ncomma = 0 ;
    int  digit ;
    int  comma ;
    int  i ;

    assert( 2 <= len ) ;

    if ( 0 == num )
    {
        buf [0] = '0' ;
        buf [1] = '\0'; ;
        return 2 ;
    }

    ndigit = n_digit( num ) ;
    ncomma = ( ndigit - 1 ) / 3 ;

    if ( (int)len < ( ndigit + ncomma + 1 ) )
    {
        return -1 ;
    }

    i = ndigit + ncomma ;

    buf [i] = '\0' ;
    comma = 0 ;
    while ( 0 < i )
    {
        if ( 3 == comma )
        {
            i -= 1 ;
            buf [i] = ',' ;
            comma = 0 ;
        }
        else
        {
            digit = num % 10 ;
            i -= 1 ;
            buf [i] = '0' + digit ;
            num = num / 10 ;
            comma += 1 ;
        }
    }

    return ndigit + ncomma + 1 ;  /* 1 for NULL */
}


static ngx_int_t  
get_int_from_query( ngx_http_request_t  * r, char  * name, size_t  len )
{
    ngx_str_t   val = { .len = 0, .data = NULL } ;

    if ( ngx_http_arg( r, (u_char *) name, len, &val ) == NGX_OK ) 
    {
        if ( val.len == 0 )
            return -1 ;
        
        return ngx_atoi( val.data, val.len ) ;
    }
    else
        return -1 ;
}


static ngx_int_t
get_str_from_query( ngx_http_request_t  * r, char  * name, size_t  len, ngx_str_t  * val )
{
    if ( NULL == val )
        return -1 ;

    val->len = 0 ;
    val->data = NULL ;
    if ( ngx_http_arg( r, (u_char *) name, len, val ) != NGX_OK ) 
        return -1 ;
        
    return 0 ;
}


/* 
   A column number can be one from 0 to 9.
 */
static const char *  
sortingColumns(ngx_http_request_t *r)
{
    static const char  * default_columns = "7r" ;
    ngx_str_t  val ;
    char  * columns ;
    int  rc ;

    rc = get_str_from_query( r, "sort", 4, &val ) ;
    if ( rc < 0 )
        return default_columns ;

    if ( val.len == 0 || val.data == NULL )
        return default_columns ;

    if ( 2 < val.len )  /* 2 is the maximum len */
        return default_columns ;
    
    columns = ngx_pcalloc( r->pool, 4 ) ;
    if ( columns == NULL )
        return default_columns ;
    
    ngx_memcpy( columns, val.data, val.len ) ;
    return columns ;
}


/* coped from ngx_http_gzip_ratio_variable()@ngx_http_gzip_filter_module.c  */
static  float
get_gzip_ratio(size_t zin, size_t zout)
{
    ngx_uint_t  zint, zfrac;
    float       ratio = 0.0;

    if (zin == 0 || zout == 0)
        return ratio;

    zint = (ngx_uint_t) (zin / zout);
    zfrac = (ngx_uint_t) ((zin * 100 / zout) % 100);
    
    if ((zin * 1000 / zout) % 10 > 4) {
        zfrac++;

	if (zfrac > 99)	{
	    zint++;
	    zfrac = 0;
	}
    }

    ratio = zint + ((float) zfrac / 100.0);

    return ratio;
}


static ngx_int_t  
how_long_ago_used(time_t  last_sec)
{
    ngx_time_t  *tp;
    ngx_int_t    sec;

    tp = ngx_timeofday();
    sec = tp->sec - last_sec;
    sec = sec < 0 ? 0 : sec;

    return sec;
}


static ngx_int_t  
set_refresh_header_field(ngx_http_request_t  *r)
{
    ngx_int_t  refresh;

    refresh = get_int_from_query(r, "refresh", 7);

    if (MIN_REFRESH_VALUE < refresh && refresh <= MAX_REFRESH_VALUE) {
        ngx_table_elt_t  *h;
	u_char           *refresh_value;

	h = ngx_list_push(&r->headers_out.headers);
	if (NULL == h)
	    return NGX_HTTP_INTERNAL_SERVER_ERROR;
	refresh_value = ngx_pnalloc(r->pool, 32);
	if (refresh_value == NULL) 
	    return NGX_HTTP_INTERNAL_SERVER_ERROR;
	else
	    memset(refresh_value, 0, 32);

	h->hash = 1;
	h->key.len = sizeof("Refresh") - 1;
	h->key.data = (u_char *) "Refresh";
	ngx_sprintf(refresh_value, "%d", refresh);
	h->value.data = refresh_value;
	h->value.len = strlen((const char *) h->value.data);
	    
	r->headers_out.refresh = h;
    }

    return 0;
}


static u_char  *
get_hostname(ngx_http_request_t  *r)
{
    u_char  *hostname = NULL;

    hostname = ngx_pnalloc(r->pool, ngx_cycle->hostname.len + 1);
    if (hostname == NULL)
        return NULL;

    ngx_cpystrn(hostname, ngx_cycle->hostname.data, ngx_cycle->hostname.len + 1);  

    return hostname;
}


static ngx_chain_t *
put_header( ngx_http_request_t  * r, char  * html_header )
{
    ngx_chain_t  * c ;
    ngx_buf_t    * b ;

    b = ngx_create_temp_buf( r->pool, strlen( html_header ) + 1 ) ;
    if ( b == NULL ) 
        return NULL ;
    c = ngx_pcalloc( r->pool, sizeof( ngx_chain_t ) ) ;
    if ( c == NULL ) 
        return NULL ;

    b->last = ngx_sprintf( b->last, html_header ) ;
    c->buf = b ;
    c->next = NULL ;

    return c ;
}


static ngx_chain_t *
put_server_info(ngx_http_request_t  *r)
{
    ngx_chain_t  *c;
    ngx_buf_t  *b;
    u_char  *hostname; 
    size_t  size ;

    size = sizeof(SERVER_INFO) + ngx_cycle->hostname.len + sizeof(NGINX_VERSION) + sizeof("<hr /><br>");
    b = ngx_create_temp_buf(r->pool, size);
    if (b == NULL) 
        return NULL;
    c = ngx_pcalloc(r->pool, sizeof(ngx_chain_t));
    if (c == NULL) 
        return NULL;

    hostname = get_hostname(r);
    if (hostname == NULL)
        return NULL;

    b->last = ngx_sprintf(b->last, SERVER_INFO, hostname, NGINX_VERSION);
    b->last = ngx_sprintf(b->last, "<hr /><br>"); 

    c->buf = b;
    c->next = NULL;

    return c;
}

#define  MAX_DIGITS  32
static ngx_chain_t *
put_connection_stat(ngx_http_request_t  *r)
{
    char  s_waiting [MAX_DIGITS] ;
    char  s_reading [MAX_DIGITS] ;
    char  s_writing [MAX_DIGITS] ;
    char  s_free [MAX_DIGITS] ;
    ngx_atomic_int_t  waiting, reading, writing ;
    worker_score  *ws;
    ngx_chain_t  * c ;
    ngx_buf_t  * b ;
    size_t  size = 0 ;
    int  free = 0 ;
    u_int32_t  i ;

    waiting = *ngx_stat_waiting ; 
    reading = *ngx_stat_reading ;
    writing = *ngx_stat_writing ;

    size += sizeof( TABLE_HEADER_CONN ) ;
    size += sizeof( "<tr align=right><td> %s </td><td> %s </td><td> %s </td><td> %s </td></tr></table><br>\n" ) + MAX_DIGITS * 4 ;

    b = ngx_create_temp_buf( r->pool, size ) ;
    if ( b == NULL ) 
        return NULL ;
    c = ngx_pcalloc( r->pool, sizeof( ngx_chain_t ) ) ;
    if ( c == NULL ) 
        return NULL ;

    for ( i = 0 ; i < ngx_num_workers ; i++ )
    {
        ws = (worker_score *) ((char *)workers + WORKER_SCORE_LEN * i) ;

        if ( ngx_cycle->connection_n < ws->active_conn )
            ngx_log_error( NGX_LOG_EMERG, r->connection->log, 0,
                           "put_connection_stat(): ngx_cycle->connection_n( %lu ) < ws->active_conn( %lu )", 
                           ngx_cycle->connection_n, ws->active_conn ) ;
        assert( ws->active_conn <= ngx_cycle->connection_n ) ;
        free += ngx_cycle->connection_n - ws->active_conn ;
    }

    to_string( waiting, MAX_DIGITS, s_waiting ) ;
    to_string( reading, MAX_DIGITS, s_reading ) ;
    to_string( writing, MAX_DIGITS, s_writing ) ;
    to_string( free,    MAX_DIGITS, s_free ) ;

    b->last = ngx_sprintf( b->last, TABLE_HEADER_CONN ) ;
    b->last = ngx_sprintf( b->last, "<tr align=right><td> %s </td><td> %s </td><td> %s </td><td> %s </td></tr></table><br>\n", 
                           s_waiting, s_reading, s_writing, s_free ) ;

    c->buf = b ;
    c->next = NULL ;
    
    return c ;
}


static ngx_chain_t *
put_cumulative_stat(ngx_http_request_t  *r)
{
    char  s_accepted [MAX_DIGITS] ;
    char  s_handled [MAX_DIGITS] ;
    char  s_requests [MAX_DIGITS] ;
    ngx_atomic_int_t  accepted, handled, requests ;
    ngx_chain_t  * c ; 
    ngx_buf_t   * b ;
    size_t  size = 0 ;

    accepted = *ngx_stat_accepted ;
    handled = *ngx_stat_handled ;
    requests = *ngx_stat_requests ;

    size += sizeof( TABLE_HEADER_CUMULATED ) ;
    size += sizeof( "<tr align=right><td> %s </td><td> %s </td><td> %s </td></tr></table><br>\n" ) + MAX_DIGITS * 3 ;

    b = ngx_create_temp_buf( r->pool, size ) ;
    if ( b == NULL ) 
        return NULL ;
    c = ngx_pcalloc( r->pool, sizeof( ngx_chain_t ) ) ;
    if ( c == NULL ) 
        return NULL ;

    to_string( accepted, 32, s_accepted ) ;
    to_string( handled, 32, s_handled ) ;
    to_string( requests, 32, s_requests ) ;

    b->last = ngx_sprintf( b->last, TABLE_HEADER_CUMULATED ) ;
    b->last = ngx_sprintf( b->last, "<tr align=right><td> %s </td><td> %s </td><td> %s </td></tr></table><br>\n", 
                           s_accepted, s_handled, s_requests ) ;

    c->buf = b ;
    c->next = NULL ;
    
    return c ;
}


static ngx_chain_t *
put_ssl_stat( ngx_http_request_t  * r )
{
    char  s_handshakes [MAX_DIGITS] ;
    char  s_tickets [MAX_DIGITS] ;
    char  s_cachehit [MAX_DIGITS] ;
    char  s_cachemiss [MAX_DIGITS] ;

    ngx_atomic_int_t  handshakes, reused, cachehit, cachemiss ;
    ngx_atomic_int_t  tickets ;
    ngx_chain_t  * c ; 
    ngx_buf_t   * b ;
    size_t  size = 0 ;
    
    handshakes = *ngx_stat_ssl_handshakes ;
    reused = *ngx_stat_reused_sessions ;
    cachehit = *ngx_stat_session_cache_hits ;
    cachemiss = *ngx_stat_session_cache_misses ;

    size += sizeof( TABLE_HEADER_SSL ) ;
    size += sizeof( "<tr align=right><td> %s </td><td> %s </td><td> %s </td><td> %s </td> </tr></table><br>\n" ) + MAX_DIGITS * 4 ;

    b = ngx_create_temp_buf( r->pool, size ) ;
    if ( b == NULL ) 
        return NULL ;
    c = ngx_pcalloc( r->pool, sizeof( ngx_chain_t ) ) ;
    if ( c == NULL ) 
        return NULL ;

    b->last = ngx_sprintf( b->last, TABLE_HEADER_SSL ) ;
    /* 
       Reused tickets = reused sessions - ( session cache hits + session cache misses )
     */
    tickets = 0 ;
    if ( cachehit < reused )
        tickets = reused - cachehit ;

    to_string( handshakes, MAX_DIGITS, s_handshakes ) ;
    to_string( tickets, MAX_DIGITS, s_tickets ) ;
    to_string( cachehit, MAX_DIGITS, s_cachehit ) ;
    to_string( cachemiss, MAX_DIGITS, s_cachemiss ) ;

    b->last = ngx_sprintf( b->last, "<tr align=right><td> %s </td><td> %s </td><td> %s </td><td> %s </td></tr></table><br>\n", 
                           s_handshakes, s_tickets, s_cachehit, s_cachemiss );

    c->buf = b ;
    c->next = NULL ;
    
    return c ;
}


static inline ngx_uint_t
dec_qps_index(ngx_uint_t index)
{
    return index == 0 ? RECENT_PERIOD - 1 : index - 1;
}


static ngx_chain_t *
put_throughput_status( ngx_http_request_t  * r )
{
    worker_score  *ws;
    ngx_time_t    *tp;
    ngx_chain_t   *c;
    ngx_buf_t     *b;
    uint32_t       cnt_for_10_sec = 0;
    uint32_t       cnt_for_60_sec = 0;
    uint32_t       current;
    uint32_t       past;
    uint32_t       index;
    uint32_t       tmp_idx;
    uint32_t       i, j;
    size_t  size;

    assert( TIME_60_SEC <= RECENT_PERIOD ) ;

    tp = ngx_timeofday() ;
    current = (uint32_t) tp->sec ;
    current -= 1 ;
    index = current & RECENT_MASK ;

    size = sizeof("<b>Requests/sec: %.02f (last %2d seconds), %.02f (last %2d seconds) &nbsp; &nbsp; at %s</b><br><br>");
    size += 7 + 2 + 7 + 2;
    size += sizeof( CURRENT_TIME ) ;
        
    b = ngx_create_temp_buf( r->pool, size ) ;
    if ( b == NULL ) 
        return NULL ;

    c = ngx_pcalloc( r->pool, sizeof( ngx_chain_t ) ) ;
    if ( c == NULL ) 
        return NULL ;

    for ( i = 0 ; i < ngx_num_workers ; i++ ) 
    {
	ws = (worker_score *) ((char *)workers + WORKER_SCORE_LEN * i);

	tmp_idx = index;
	past = current;
	for ( j = 0; j < TIME_60_SEC ; j++) 
        {
	    if ( past == ws->recent_request_cnt [tmp_idx].time ) 
            {
	        cnt_for_60_sec += ws->recent_request_cnt [tmp_idx].cnt ;
		if ( j < TIME_10_SEC )
		    cnt_for_10_sec += ws->recent_request_cnt [tmp_idx].cnt ;
	    }

	    tmp_idx = dec_qps_index( tmp_idx ) ;
	    past -= 1 ;
	}
    }

    b->last = ngx_sprintf( b->last, "<b>Requests/sec: %.02f (last %2d seconds), %.02f (last %2d seconds) &nbsp; &nbsp; at %s</b><br><br>", 
                           (float)cnt_for_10_sec / (float)TIME_10_SEC, TIME_10_SEC, 
                           (float)cnt_for_60_sec / (float)TIME_60_SEC, TIME_60_SEC, 
                           CURRENT_TIME ) ;
    c->buf = b ;
    c->next = NULL ;

    return c ; 
}


static ngx_chain_t *
put_worker_status(ngx_http_request_t *r)
{
    worker_score  *ws;
    ngx_chain_t   *c;
    ngx_buf_t     *b;
    uint32_t       hz = sysconf(_SC_CLK_TCK);
    uint32_t       i ;
    size_t  size;
    size_t  sizePerWorker = 0 ;

    size = sizeof( TABLE_HEADER_WORKER ) ;

    sizePerWorker += sizeof( "<tr><td align=center>%4d</td>") + 4 ;
    sizePerWorker += sizeof( "<td> %5d </td>") + 8; /* must greater or equal to the size of /proc/sys/kernel/pid_max */
    sizePerWorker += sizeof( "<td align=right> %d </td>") + NGX_INT64_LEN;
    sizePerWorker += sizeof( "<td align=center><b> %c </b></td>");
    sizePerWorker += sizeof( "<td> %.2f </td>") + 5; 
    sizePerWorker += sizeof( "<td align=right> %.2f </td></tr>") + NGX_INT64_LEN; 
    sizePerWorker += sizeof( "<td align=right> %d </td>") + NGX_INT64_LEN;

    size += sizePerWorker * ngx_num_workers;
    size += sizeof("</table><br>\n");
        
    b = ngx_create_temp_buf(r->pool, size);
    if (b == NULL) 
        return NULL;

    c = ngx_pcalloc(r->pool, sizeof(ngx_chain_t));
    if (c == NULL) 
        return NULL;

    b->last = ngx_sprintf( b->last, TABLE_HEADER_WORKER ) ;
    for (i = 0; i < ngx_num_workers; i++) {
	ws = (worker_score *) ((char *)workers + WORKER_SCORE_LEN * i);

	b->last = ngx_sprintf( b->last, "<tr><td align=center>%4d</td>", i ) ;
	b->last = ngx_sprintf( b->last, "<td> %5d </td>", ws->pid ) ;
	b->last = ngx_sprintf( b->last, "<td align=right> %d </td>", ws->access_count ) ;
	b->last = ngx_sprintf( b->last, "<td align=center><b> %c </b></td>", ws->mode ) ;
	b->last = ngx_sprintf( b->last, "<td> %.2f </td>",
                              ( ws->times.tms_utime + ws->times.tms_stime +
                                ws->times.tms_cutime + ws->times.tms_cstime) / (float) hz ) ;
	b->last = ngx_sprintf( b->last, "<td align=right> %.2f </td>", (float) ws->bytes_sent / MBYTE ) ;

        if ( ngx_cycle->connection_n < ws->active_conn )
            ngx_log_error( NGX_LOG_EMERG, r->connection->log, 0,
                           "put_worker_status(): ngx_cycle->connection_n( %lu ) < ws->active_conn( %lu )", 
                           ngx_cycle->connection_n, ws->active_conn ) ;
        assert( ws->active_conn <= ngx_cycle->connection_n ) ;
	b->last = ngx_sprintf( b->last, "<td align=right> %d </td></tr>", ngx_cycle->connection_n - ws->active_conn ) ;
    }
    b->last = ngx_sprintf( b->last, "</table><br>\n" ) ;

    c->buf = b ;
    c->next = NULL ;

    return c ;
}


static ngx_chain_t *
put_recent_requests( ngx_http_request_t  * r, ngx_int_t  cnt, ngx_int_t  response_time )
{
    conn_score     *cs ;
    ngx_uint_t      i, j, k ;
    int             end = 0 ;
    ngx_chain_t   * c, *c1, *c2 ;
    ngx_buf_t     * b ;
    size_t   sizePerConn = 0 ;
    size_t   sizePerWorker ;
    int  n = 0 ;

    assert( 0 <= cnt ) ;
    
    sizePerConn += sizeof( "<tr><td align=center>%4d-%04d</td>" ) + 4 + 4 ;
    sizePerConn += sizeof( "<td> %s </td>" ) + SCORE__CLIENT_LEN ;
    sizePerConn += sizeof( "<td> %s </td>" ) + SCORE__VHOST_LEN ;
    sizePerConn += sizeof( "<td align=right> %d </td>" ) + NGX_INT64_LEN ;
    sizePerConn += sizeof( "<td align=right> %.02f </td>" ) + 5 ;
    sizePerConn += sizeof( "<td align=right> %d </td>" ) + NGX_INT64_LEN ;
    sizePerConn += sizeof( "<td align=right> %ui </td>" ) + 3 ;
    sizePerConn += sizeof( "<td align=right> %d </td>" ) + NGX_INT64_LEN ;
    sizePerConn += sizeof( "<td align=right> %d </td>" ) + NGX_INT64_LEN ;  
    sizePerConn += sizeof( "<td> %s </td></tr>" ) + SCORE__REQUEST_LEN ;

    sizePerWorker = sizePerConn * ngx_cycle->connection_n;
       
    /* 5 = sizeof("9r-9r") - 1 */
    b = ngx_create_temp_buf( r->pool, sizeof( TABLE_HEADER_REQUESTS ) + 5 + sizePerWorker ) ;  
    if (b == NULL) 
        return NULL;
    c = c1 = ngx_pcalloc( r->pool, sizeof( ngx_chain_t ) ) ;
    if ( c == NULL ) 
        return NULL ;

    c->buf = b ;
    c->next = NULL ;

    b->last = ngx_sprintf( b->last, TABLE_HEADER_REQUESTS, sortingColumns( r ) ) ;
    for ( i = 0 ; i < ngx_num_workers && ( 0 == cnt || 0 == end ) ; i++ ) 
    {
        for ( j = 0 ; j < ngx_cycle->connection_n ; j++ ) 
        {
	    k = i * ngx_cycle->connection_n + j ;
	    cs = (conn_score *) ((char *)conns + sizeof( conn_score ) * k ) ;

	    if ( cs->response_time < response_time || (time_t) 0 ==  cs->last_used )
	        continue ;
            
            if ( 0 < cnt )
            {
                if ( cnt <= n )
                {
                    end = 1 ;
                    break ;
                }
                else
                {
                    n += 1 ;
                }
            }

	    b->last = ngx_sprintf( b->last, "<tr><td align=center>%4d-%04d</td>", i, j ) ;
	    
	    b->last = ngx_sprintf( b->last, "<td> %s </td>", cs->client ) ;
	    b->last = ngx_sprintf( b->last, "<td> %s </td>", cs->vhost ) ;

	    b->last = ngx_sprintf( b->last, "<td align=right> %d </td>", cs->bytes_sent ) ;
	
	    if ( 0 != cs->zin && 0 != cs->zout )
	        b->last = ngx_sprintf( b->last, "<td align=right> %.02f </td>", get_gzip_ratio( cs->zin, cs->zout ) ) ;
	    else
	        b->last = ngx_sprintf( b->last, "<td align=center> - </td>" ) ;

	    b->last = ngx_sprintf( b->last, "<td align=right> %d </td>", how_long_ago_used( cs->last_used ) ) ;
	    b->last = ngx_sprintf( b->last, "<td align=right> %ui </td>", cs->status ) ;

	    b->last = ngx_sprintf( b->last, "<td align=right> %d </td>", cs->response_time ) ;

	    if (0 <= cs->upstream_response_time)
	        b->last = ngx_sprintf( b->last, "<td align=right> %d </td>", cs->upstream_response_time ) ;
	    else
	        b->last = ngx_sprintf( b->last, "<td align=center><b>-</b></td>" ) ;

	    b->last = ngx_sprintf( b->last, "<td> %s </td></tr>\n", cs->request ) ;
	}

        if ( b->pos == b->last )
            continue ;

        b = ngx_create_temp_buf( r->pool, sizePerWorker ) ;
        if ( b == NULL ) 
            return NULL ;
        c2 = ngx_pcalloc( r->pool, sizeof( ngx_chain_t ) ) ;
        if ( c2 == NULL )  
            return NULL ;
        
        c2->buf = b ;
        c2->next = NULL ;
        c1->next = c2 ;
        c1 = c2 ;
    }

    assert( b->last <= b->end ) ;
    if ( (unsigned)( b->end - b->last ) < sizeof( "</tbody></table><br>\n" ) )
    {
        b = ngx_create_temp_buf( r->pool, sizeof( "</tbody></table><br>\n" ) ) ;
        if (b == NULL) 
            return NULL;

        c2 = ngx_pcalloc(r->pool, sizeof(ngx_chain_t));
        if (c2 == NULL) 
            return NULL;
        
        c2->buf = b;
        c2->next = NULL;
        c1->next = c2;
    }

    b->last = ngx_sprintf(b->last, "</tbody></table><br>\n");

    return c;
}


static ngx_chain_t  *
put_footer( ngx_http_request_t  * r )
{
    ngx_chain_t  * c ;
    ngx_buf_t  * b ;
    size_t  size = 0 ;

    size += sizeof( "<hr />" ) ;
    size += sizeof( TABLE_SHORTENED ) ;
    size += sizeof( "<br>" ) ;
    size += sizeof( TABLE_HELP ) ;
    size += sizeof( HTML_TAIL ) ;
    
    b = ngx_create_temp_buf( r->pool, size ) ;
    if ( b == NULL ) 
        return NULL ;
    c = ngx_pcalloc( r->pool, sizeof( ngx_chain_t ) ) ;
    if ( c == NULL ) 
        return NULL ;

    b->last = ngx_sprintf( b->last, "<hr />" ) ;
    b->last = ngx_sprintf( b->last, TABLE_SHORTENED ) ;
    b->last = ngx_sprintf( b->last, "<br>" ) ;
    b->last = ngx_sprintf( b->last, TABLE_HELP ) ;
    b->last = ngx_sprintf( b->last, HTML_TAIL ) ;

    c->buf = b ;
    c->next = NULL ;

    return c ;
} 


static inline ngx_chain_t *
goto_tail( ngx_chain_t  * c )
{
    ngx_chain_t  * last = c ;

    assert( last != NULL ) ;

    while ( last->next != NULL )
        last = last->next ;

    return last ;
}


static inline off_t
get_contentLength(ngx_chain_t  *c)
{
    off_t  l = 0;

    while (c != NULL) {
        l += ngx_buf_size(c->buf);
        c = c->next;
    }
    
    return l;
}


static ngx_int_t 
ngx_http_html_status_handler(ngx_http_request_t *r)
{
    ngx_chain_t  * c_head ;
    ngx_chain_t  * c_tail ;
    ngx_int_t   res_time ;
    ngx_int_t   rr ;
    ngx_int_t   rc ;

    if ( NGX_HTTP_GET != r->method )
        return NGX_HTTP_NOT_ALLOWED ;

    rc = ngx_http_discard_request_body( r ) ;
    if ( rc != NGX_OK ) 
        return rc ;

    r->headers_out.content_type.len  = sizeof( "text/html; charset=ISO-8859-1" ) - 1 ;
    r->headers_out.content_type.data = (u_char *) "text/html; charset=ISO-8859-1" ;

    rc = set_refresh_header_field( r ) ;
    if ( rc != NGX_OK )
        return rc ;

    if ( NULL == ( c_head = put_header( r, HTML_HEADER ) ) )
        goto e500 ;
    c_tail = goto_tail( c_head ) ;

    if ( NULL == ( c_tail->next = put_server_info( r ) ) )
        goto e500 ;
    c_tail = goto_tail( c_tail ) ;

    if ( NULL == ( c_tail->next = put_throughput_status( r ) ) )
        goto e500 ;
    c_tail = goto_tail( c_tail ) ;

    if ( NULL == ( c_tail->next = put_connection_stat( r ) ) ) 
        goto e500 ;
    c_tail = goto_tail( c_tail ) ;

    if ( NULL == ( c_tail->next = put_cumulative_stat( r ) ) ) 
        goto e500 ;
    c_tail = goto_tail( c_tail ) ;

    if ( NULL == ( c_tail->next = put_ssl_stat( r ) ) ) 
        goto e500 ;
    c_tail = goto_tail( c_tail ) ;

    if ( NULL == ( c_tail->next = put_worker_status( r ) ) ) 
        goto e500 ;
    c_tail = goto_tail( c_tail ) ;

    rr = get_int_from_query( r, "rr", 2 ) ;
    if ( rr < 0 )
        rr = DEFAULT_NUM_REQ ;

    res_time = get_int_from_query( r, "time", 4 ) ;
    if ( res_time < 0 )
        res_time = 0 ; 

    if ( NULL == ( c_tail->next = put_recent_requests( r, rr, res_time ) ) ) 
        goto e500 ;
    
    c_tail = goto_tail( c_tail ) ;

    if ( NULL == ( c_tail->next = put_footer( r ) ) )
        goto e500 ;
    c_tail = goto_tail( c_tail ) ;

    c_tail->buf->last_buf = 1 ;

    r->headers_out.status = NGX_HTTP_OK ;
    r->headers_out.content_length_n = get_contentLength( c_head ) ;

    rc = ngx_http_send_header( r ) ;
    if ( NGX_ERROR == rc || NGX_OK < rc || r->header_only ) 
        return rc ;

    return ngx_http_output_filter( r, c_head ) ; 

e500:
    return NGX_HTTP_INTERNAL_SERVER_ERROR ;
}


static ngx_int_t 
ngx_http_status_handler(ngx_http_request_t *r)
{
    return ngx_http_html_status_handler( r ) ;
}


static char *
ngx_http_set_status(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_status_handler ;

    return NGX_CONF_OK;
}
