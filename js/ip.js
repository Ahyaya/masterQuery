var whois = {
    root: 'https://whois.pconline.com.cn',
    lableIp:function(id,ip){
        var s=document.body.appendChild(document.createElement("script"));
        s.src=this.root+"/jsLabel.jsp?ip="+ip+"&id="+id;
        s.rel="no-referrer";
    }
}
function labelIp(id,ip){
    whois.lableIp(id,ip);
}
