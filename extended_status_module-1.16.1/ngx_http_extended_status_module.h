
#define  HTML_HEADER    "<html><head><title>Nginx Status</title>\n" \
        "<!--<version>2</version>-->" \
        "<script type=text/javascript src=tablesort.min.js></script>\n" \
        "<style type=text/css><!--\n" \
        "body{font:bold 15px Georgia, Helvetica, sans-serif;color:#4f6b72;}\n" \
        "table{border-top:1px solid #e5eff8;border-right:1px solid #e5eff8;border-collapse:collapse;}\n" \
        "th{font:bold 10px \"Century Gothic\", \"Trebuchet MS\", Helvetica, sans-serif;letter-spacing:1px;text-transform:uppercase;background:#f4f9fe;color:#66a3d3;border-bottom:1px solid #e5eff8;border-left:1px solid #e5eff8;padding:8px 5px;}\n" \
        "td{border-bottom:1px solid #e5eff8;border-left:1px solid #e5eff8;}\n" \
        "tbody td{font:13px Calibri,\"Trebuchet MS\", Helvetica, sans-serif;padding:5px;}\n" \
        "tr:hover{background: #d0dafd;color:#000000}\n" \
        "--></style>\n" \
        "</head>\n<body>\n"

#define  HTML_TAIL        "\n</body></html>"

#define  SERVER_INFO      "<h1> Nginx Server Status for %s</h1>\n<dl><dt>Server Version: Nginx/%s </dt></dl>\n"

#define  CURRENT_TIME  \
        "<script type=text/javascript> var date = new Date() ; document.write( date.toLocaleString() );</script>"

#define  TABLE_HEADER_CONN \
        "<b>Connections</b><br>\n<table border=0><tr><th>Waiting</th><th>Reading</th><th>Writing</th><th>Free</th></tr>\n" 

#define  TABLE_HEADER_CUMULATED  \
        "<b>Cumulated Connections and Requests</b><br>\n<table border=0><tr><th>server accepts</th><th>handled</th><th>requests</th></tr>\n" 

#define  TABLE_HEADER_SSL  \
        "<b>Cumulated SSL Sessions</b><br>\n<table border=0><tr><th>SSL Handshakes</th><th>Reused Tickets</th><th>Session ID Hits</th><th>Session ID Misses</th></tr>\n" 

#define  TABLE_HEADER_WORKER   "<b>Worker processes</b><br>\n" \
        "<table border=0><tr><th>Worker</th><th>PID</th><th>Requests</th><th>Mode</th><th>CPU</th>" \
        "<th>Mbytes</th><th>Free conn.</th></tr>\n" 

#define  TABLE_HEADER_REQUESTS  "<b>Recent Requests</b><br>\n" \
        "<table class=sortable-onload-%s cellspacing=1 border=0 cellpadding=1>\n" \
        "<thead><tr><th class=sortable>Worker & Conn. Slot</th>\n" \
        "<th class=sortable>Client</th><th class=sortable>VHost</th><th class=sortable>Bytes</th>\n" \
        "<th class=sortable>Gzip Ratio</th><th class=sortable>SS</th><th class=sortable>Status</th>\n" \
        "<th class=sortable>TIME</th><th class=sortable>Proxy TIME</th><th class=sortable>Request</th></tr></thead><tbody>\n"

#define  TABLE_SHORTENED  "<table>\n"  \
        "<tr><th>PID</th><td>OS process ID</td></tr>\n" \
        "<tr><th>Requests</th><td>Number of requests serviced by this worker process</td></tr>\n" \
        "<tr><th>MODE</th><td> <b>-</b>: Waiting for request, <b>R</b>: Reading request, <b>W</b>: Sending reply, <b>L</b>: Logging</td></tr>\n" \
        "<tr><th>CPU</th><td>Accumulated CPU usage in seconds</td></tr>\n" \
        "<tr><th>Gzip Ratio</th></td><td> Ratio of original size to compressed size</td></tr>" \
        "<tr><th>SS</th><td>Seconds since the request completion</td></tr>\n" \
        "<tr><th>TIME</th><td>Response time in milliseconds. 0 means the value is less than 1 millisecond</td></tr>\n" \
        "<tr><th>Proxy TIME</th><td> Proxy response time in milliseconds. 0 means the value is less than 1 millisecond</td></tr>\n" \
        "</table>\n" 

#define  TABLE_HELP  "<b> Arguments </b><br>" \
        "<table>" \
        "<tr><th> rr   </th><td> Specifies the number of requests to be shown. default: 30 <br>  \
                                 Zero means \"as many as possible\"  </td></tr>\n" \
        "<tr><th> time </th><td> Only the requests having response time greater or equal than this value can be displayed </td></tr>\n" \
        "<tr><th> sort </th><td> Sorting columns of the recent requests table. default: 7r </td></tr>\n" \
        "<tr><th> refresh </th><td> Refresh interval </td></tr>\n" \
        "</table>\n"

#define  MODE_LIST  "<b>Mode List</b><br>" \
                    "<table>" \
                    "<tr><th>-</th><td>Waiting for request</td></tr>\n" \
                    "<tr><th>R</th><td>Reading request</td></tr>\n" \
                    "<tr><th>W</th><td>Sending reply</td></tr>\n" \
                    "<tr><th>L</th><td>Logging</td></tr>\n" \
                    "<tr><th>I</th><td>Inactive connection</td></tr>\n" \
                    "</table>\n"

#define  MBYTE  1048576.0

#define  DEFAULT_NUM_REQ     30

#define  MIN_REFRESH_VALUE    0
#define  MAX_REFRESH_VALUE   60

#define  TIME_10_SEC  10
#define  TIME_60_SEC  60
