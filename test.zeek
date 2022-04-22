global response_404_unique:table[addr] of set[string];
global response_404:table[addr] of count;
global response:table[addr] of count;
event http_reply(c:connection,version:string,code:count,reason:string)
{
local ip=c$id$orig_h;
local uri=c$http$uri;
local status=c$http$status_code;
if(ip in response)
{
response[ip]+=1;
if(status==404)
{
response_404[ip]+=1;
add response_404_unique[ip][uri];
}
}
else
{
response[ip]=1;
if(status==404)
{
response_404[ip]=1;
response_404_unique[ip]=set(uri);
}
}
}
event zeek_done()
{
for([ip],p in response)
{
local sum=p;
local sum_404=response_404[ip];
local sum_404_unique=|response_404_unique[ip]|;
if(sum_404>2&&sum_404*5>sum&&sum_404_unique*2>sum_404)
{
print ip," is a scanner with ",sum_404," scan attemps on ",sum_404_unique," urls";
}
}
}
