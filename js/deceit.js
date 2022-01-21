document.getElementsByName("hiddenFlag_1").forEach(function(d){
    d.onclick=function(){alert("人家服是隐藏的，你在想屁吃")};
    d.href="javascript:void(0)";
    d.getAttributeNode("target").value='';
});