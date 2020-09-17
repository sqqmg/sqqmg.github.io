
var pnum = '';

function jj_lxfs(){
	if(pnum){
		document.write("如需取名、改名，请联系大师提供一对一服务：" + pnum);
	}
    
}

function footer_lxfs(){
	if(pnum){
		document.write("如需起名请联系大师提供一对一起名服务：" + pnum);
	}
}

$(function(){
    if(pnum){
    	$('#lxfs').text("如需起名请联系大师提供一对一起名服务：" + pnum);
    }
});
