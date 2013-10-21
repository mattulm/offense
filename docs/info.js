function ClientInfo() {
	strClientInfo="--------------Browser----------------"+"\r\n"+
	"availHeight= "+window.screen.availHeight+"\r\n"+
	"availWidth= "+window.screen.availWidth+"\r\n"+
	"bufferDepth= "+window.screen.bufferDepth+"\r\n"+
	"colorDepth= "+window.screen.colorDepth+"\r\n"+
	"colorEnable= "+window.navigator.cookieEnabled+"\r\n"+
	"cpuClass= "+window.navigator.cpuClass+"\r\n"+
	"height= "+window.screen.height+"\r\n"+
	"javaEnable= "+window.navigator.javaEnabled()+"\r\n"+
	"platform= "+window.navigator.platform+"\r\n"+
	"systemLanguage= "+window.navigator.systemLanguage+"\r\n"+
	"userLanguage= "+window.navigator.userLanguage+"\r\n"+
	"width= "+window.screen.width+"\r\n"+
	"--------------Browser------------------"
	"window.parent.location: "+window.parent.loation+"\r\n"+
	"Browser Name: "+window.appName+"\r\n"+
	"Browser Version: "+navigator.appVersion+"\r\n"+
	"Browser Code Name: "+navigator.appCodeName+"\r\n"+
	"User Agent: "+navigator.userAgent+"\r\n";
	retrun strClientInfo;
}