﻿<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<html xmlns:v>
<head>
<meta http-equiv="X-UA-Compatible" content="IE=Edge"/>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta HTTP-EQUIV="Pragma" CONTENT="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="-1">
<link rel="shortcut icon" href="images/favicon.png">
<link rel="icon" href="images/favicon.png">
<title>【Merlin Clash】</title>
<link rel="stylesheet" type="text/css" href="index_style.css">
<link rel="stylesheet" type="text/css" href="form_style.css">
<link rel="stylesheet" type="text/css" href="usp_style.css">
<link rel="stylesheet" type="text/css" href="css/element.css">
<link rel="stylesheet" type="text/css" href="/device-map/device-map.css">
<link rel="stylesheet" type="text/css" href="/js/table/table.css">
<link rel="stylesheet" type="text/css" href="/res/layer/theme/default/layer.css">
<link rel="stylesheet" type="text/css" href="/res/softcenter.css">
<link rel="stylesheet" type="text/css" href="/res/merlinclash.css">
<script type="text/javascript" src="/state.js"></script>
<script type="text/javascript" src="/popup.js"></script>
<script type="text/javascript" src="/help.js"></script>
<script type="text/javascript" src="/js/jquery.js"></script>
<script type="text/javascript" src="/general.js"></script>
<script type="text/javascript" language="JavaScript" src="/js/table/table.js"></script>
<script type="text/javascript" language="JavaScript" src="/client_function.js"></script>
<script type="text/javascript" src="/res/mc-menu.js"></script>
<script type="text/javascript" src="/res/softcenter.js"></script>
<script type="text/javascript" src="/res/mc-tablednd.js"></script>
<script type="text/javascript" src="/help.js"></script>
<script type="text/javascript" src="/switcherplugin/jquery.iphone-switch.js"></script>
<script type="text/javascript" src="/validator.js"></script>
<script>
var db_merlinclash={};
var _responseLen;
var x = 5;
var noChange = 0;
var node_max = 0;
var acl_node_max = 0;
var kpacl_node_max = 0;
var devices_node_max = 0;
var whitelists_node_max = 0;
var kcp_node_max = 0;
var kpyacl_node_max = 0;
var rule_node_max = 0;
var ipports_node_max = 0;
var nokpacl_node_max = 0;
var unmacl_node_max = 0;
var edit_falg;
var log_count = 0;
var select_count = 0;
var dy_count = 0;
var yamlview_count = 0;
var init_count = 0;
var init_kpcount = 0;
var init_kpcount2 = 0;
var init_hostcount = 0;
var init_nokpaclcount = 0;
var init_aclcount = 0;
var init_advancedcount = 0;
var init_unblockcount = 0;
function init() {
	show_menu(menu_hook);
	//定时作业下拉数据
	load_cron_params();
	
	get_dbus_data();
	
	//定时作业下拉切换显示
	show_job();	
	//获取相关状态
	get_clash_status_front();
	//栏目点击切换
	toggle_func();
	//版本检查
	version_show();	
	//下拉框获取配置文件名
	yaml_select();
	//host编辑区
	host_select();
	
	dy_for_version();
	//DC用户初始刷新
	dc_init();
	if(E("merlinclash_enable").checked){
		merlinclash.checkIP();
	}	
	notice_show();
}

function get_dbus_data() {
	$.ajax({
		type: "GET",
		url: "/_api/merlinclash",
		async: false,
		success: function(data) {
			db_merlinclash = data.result[0];
			E("merlinclash_enable").checked = db_merlinclash["merlinclash_enable"] == "1";
			E("merlinclash_watchdog").checked = db_merlinclash["merlinclash_watchdog"] == "1";
			E("merlinclash_kcpswitch").checked = db_merlinclash["merlinclash_kcpswitch"] == "1";
			if(db_merlinclash["merlinclash_linuxver"] >= 41){
				E("merlinclash_ipv6switch").checked = db_merlinclash["merlinclash_ipv6switch"] == "1";
			}
			E("merlinclash_cirswitch").checked = db_merlinclash["merlinclash_cirswitch"] == "1";
			E("merlinclash_startlog").checked = db_merlinclash["merlinclash_startlog"] == "1";
			E("merlinclash_dnsgoclash").checked = db_merlinclash["merlinclash_dnsgoclash"] == "1";
			E("merlinclash_dnsclear").checked = db_merlinclash["merlinclash_dnsclear"] == "1";
			E("merlinclash_closeproxy").checked = db_merlinclash["merlinclash_closeproxy"] == "1";
			E("merlinclash_passkpswitch").checked = db_merlinclash["merlinclash_passkpswitch"] == "1";
			E("merlinclash_dashboardswitch").checked = db_merlinclash["merlinclash_dashboardswitch"] == "1";
			E("merlinclash_googlehomeswitch").checked = db_merlinclash["merlinclash_googlehomeswitch"] == "1";
			E("merlinclash_check_dlercloud").checked = db_merlinclash["merlinclash_check_dlercloud"] == "1";
			E("merlinclash_check_aclrule").checked = db_merlinclash["merlinclash_check_aclrule"] == "1";
			E("merlinclash_check_controllist").checked = db_merlinclash["merlinclash_check_controllist"] == "1";
			E("merlinclash_check_unblock").checked = db_merlinclash["merlinclash_check_unblock"] == "1";
			E("merlinclash_check_kp").checked = db_merlinclash["merlinclash_check_kp"] == "1";
			E("merlinclash_check_cdns").checked = db_merlinclash["merlinclash_check_cdns"] == "1";
			E("merlinclash_check_scriptedit").checked = db_merlinclash["merlinclash_check_scriptedit"] == "1";
			E("merlinclash_check_chost").checked = db_merlinclash["merlinclash_check_chost"] == "1";
			E("merlinclash_check_kcp").checked = db_merlinclash["merlinclash_check_kcp"] == "1";
			E("merlinclash_check_cusport").checked = db_merlinclash["merlinclash_check_cusport"] == "1";
			E("merlinclash_check_clashimport").checked = db_merlinclash["merlinclash_check_clashimport"] == "1";
			E("merlinclash_check_xiaobai").checked = db_merlinclash["merlinclash_check_xiaobai"] == "1";
			E("merlinclash_check_sclocal").checked = db_merlinclash["merlinclash_check_sclocal"] == "1";
			E("merlinclash_check_yamldown").checked = db_merlinclash["merlinclash_check_yamldown"] == "1";
			E("merlinclash_check_ssimport").checked = db_merlinclash["merlinclash_check_ssimport"] == "1";
			if(db_merlinclash["merlinclash_flag"] == "HND"){
				E("merlinclash_check_upcusrule").checked = db_merlinclash["merlinclash_check_upcusrule"] == "1";
			}
			E("merlinclash_check_noipt").checked = db_merlinclash["merlinclash_check_noipt"] == "1";
			E("merlinclash_check_tproxy").checked = db_merlinclash["merlinclash_check_tproxy"] == "1";
			E("merlinclash_unblockmusic_enable").checked = db_merlinclash["merlinclash_unblockmusic_enable"] == "1";
			E("merlinclash_unblockmusic_bestquality").checked = db_merlinclash["merlinclash_unblockmusic_bestquality"] == "1";
			E("merlinclash_unblockmusic_log").checked = db_merlinclash["merlinclash_unblockmusic_log"] == "1";
			E("merlinclash_unblockmusic_vip").checked = db_merlinclash["merlinclash_unblockmusic_vip"] == "1";
			//20200828+
			E("merlinclash_check_delay_cbox").checked = db_merlinclash["merlinclash_check_delay_cbox"] == "1";	
			E("merlinclash_auto_delay_cbox").checked = db_merlinclash["merlinclash_auto_delay_cbox"] == "1";
			if(db_merlinclash["merlinclash_flag"] == "HND"){
				E("merlinclash_customrule_cbox").checked = db_merlinclash["merlinclash_customrule_cbox"] == "1";
			}else{
				E("merlinclash_cdn_cbox").checked = db_merlinclash["merlinclash_cdn_cbox"] == "1";
			}
			E("merlinclash_custom_cbox").checked = db_merlinclash["merlinclash_custom_cbox"] == "1";	
			E("merlinclash_urltestTolerance_cbox").checked = db_merlinclash["merlinclash_urltestTolerance_cbox"] == "1";
			E("merlinclash_interval_cbox").checked = db_merlinclash["merlinclash_interval_cbox"] == "1";
			if(db_merlinclash["merlinclash_unblockmusic_endpoint"]){
				E("merlinclash_unblockmusic_endpoint").value = db_merlinclash["merlinclash_unblockmusic_endpoint"];
			}
			if(db_merlinclash["merlinclash_unblockmusic_musicapptype"]){
				E("merlinclash_unblockmusic_musicapptype").value = db_merlinclash["merlinclash_unblockmusic_musicapptype"];
			}
			if(db_merlinclash["merlinclash_unblockmusic_platforms_numbers"]){
				E("merlinclash_unblockmusic_platforms_numbers").value = db_merlinclash["merlinclash_unblockmusic_platforms_numbers"];
			}
			if(db_merlinclash["merlinclash_urltestTolerancesel"]){
				E("merlinclash_urltestTolerancesel").value = db_merlinclash["merlinclash_urltestTolerancesel"];
			}
			if(db_merlinclash["merlinclash_intervalsel"]){
				E("merlinclash_intervalsel").value = db_merlinclash["merlinclash_intervalsel"];
			}
			if(db_merlinclash["merlinclash_flag"] != "HND"){
				if(db_merlinclash["merlinclash_subconverter_addr"]){
					E("merlinclash_subconverter_addr").value = db_merlinclash["merlinclash_subconverter_addr"];
				}
			}
			//20200828-	
			if(db_merlinclash["merlinclash_links"]){					
				E("merlinclash_links").value = Base64.decode(db_merlinclash["merlinclash_links"]);
			}
			if(db_merlinclash["merlinclash_links2"]){	
				var delinks = decodeURIComponent(Base64.decode(db_merlinclash["merlinclash_links2"]));	
				E("merlinclash_links2").value = delinks;
			}
			if(db_merlinclash["merlinclash_links3"]){
				var delinks2 = decodeURIComponent(Base64.decode(db_merlinclash["merlinclash_links3"]));
				E("merlinclash_links3").value = delinks2;
			}
			//20210916+
			if(db_merlinclash["merlinclash_uploadiniurl"]){
				var deurl = decodeURIComponent(Base64.decode(db_merlinclash["merlinclash_uploadiniurl"]));
				E("merlinclash_uploadiniurl").value = deurl;
			}
			if(db_merlinclash["merlinclash_dc_uploadiniurl"]){
				var dcdeurl = decodeURIComponent(Base64.decode(db_merlinclash["merlinclash_dc_uploadiniurl"]));
				E("merlinclash_dc_uploadiniurl").value = dcdeurl;
			}
			//20210916-
			if(db_merlinclash["merlinclash_dnsplan"]){					
				$("input:radio[name='dnsplan'][value="+db_merlinclash["merlinclash_dnsplan"]+"]").attr('checked','true');
			}
			if(db_merlinclash["merlinclash_dnshijack"]){					
				$("input:radio[name='dnshijack'][value="+db_merlinclash["merlinclash_dnshijack"]+"]").attr('checked','true');
			}
			if(db_merlinclash["merlinclash_unblockmusic_unblockplan"]){					
				$("input:radio[name='unblockplan'][value="+db_merlinclash["merlinclash_unblockmusic_unblockplan"]+"]").attr('checked','true');
			}
			if(db_merlinclash["merlinclash_clashmode"]){					
				$("input:radio[name='clashmode'][value="+db_merlinclash["merlinclash_clashmode"]+"]").attr('checked','true');
				
			}
			if(db_merlinclash["merlinclash_dnsedit_tag"]){					
				$("input:radio[name='dnsplan_edit'][value="+db_merlinclash["merlinclash_dnsedit_tag"]+"]").attr('checked','true');
			}
			if(db_merlinclash["merlinclash_linuxver"] >= 41){
				if(db_merlinclash["merlinclash_tproxymode"]){					
					$("input:radio[name='tproxymode'][value="+db_merlinclash["merlinclash_tproxymode"]+"]").attr('checked','true');
				}
			}
			if(db_merlinclash["merlinclash_iptablessel"]){					
				$("input:radio[name='iptablessel'][value="+db_merlinclash["merlinclash_iptablessel"]+"]").attr('checked','true');
			}
			
            if(db_merlinclash["merlinclash_dashboard_secret"]){					
				E("merlinclash_dashboard_secret").value = db_merlinclash["merlinclash_dashboard_secret"];
			}
			if(db_merlinclash["merlinclash_check_delay_time"]){					
				E("merlinclash_check_delay_time").value = db_merlinclash["merlinclash_check_delay_time"];
			}
			if(db_merlinclash["merlinclash_cus_port"]){					
				E("merlinclash_cus_port").value = db_merlinclash["merlinclash_cus_port"];
			}
			if(db_merlinclash["merlinclash_cus_socksport"]){					
				E("merlinclash_cus_socksport").value = db_merlinclash["merlinclash_cus_socksport"];
			}
			if(db_merlinclash["merlinclash_cus_redirsport"]){					
				E("merlinclash_cus_redirsport").value = db_merlinclash["merlinclash_cus_redirsport"];
			}
			if(db_merlinclash["merlinclash_cus_tproxyport"]){					
				E("merlinclash_cus_tproxyport").value = db_merlinclash["merlinclash_cus_tproxyport"];
			}
			if(db_merlinclash["merlinclash_cus_dnslistenport"]){					
				E("merlinclash_cus_dnslistenport").value = db_merlinclash["merlinclash_cus_dnslistenport"];
			}
			if(db_merlinclash["merlinclash_cus_dashboardport"]){					
				E("merlinclash_cus_dashboardport").value = db_merlinclash["merlinclash_cus_dashboardport"];
			}
			if(db_merlinclash["merlinclash_auto_delay_time"]){					
				E("merlinclash_auto_delay_time").value = db_merlinclash["merlinclash_auto_delay_time"];
			}
			if(db_merlinclash["merlinclash_watchdog_delay_time"]){					
				E("merlinclash_watchdog_delay_time").value = db_merlinclash["merlinclash_watchdog_delay_time"];
			}
            E("merlinclash_dc_name").value = db_merlinclash["merlinclash_dc_name"];
            E("merlinclash_dc_passwd").value = db_merlinclash["merlinclash_dc_passwd"];
			if(db_merlinclash["merlinclash_linuxver"] < 41){
				document.getElementById("tproxy").style.display="none"
				document.getElementById("tproxy_show").style.display="none"
				document.getElementById("tproxy_showcbox").style.display="none"
			}else{
				document.getElementById("tproxy").style.display=""
				document.getElementById("tproxy_show").style.display=""
				document.getElementById("tproxy_showcbox").style.display=""
			}
			if(db_merlinclash["merlinclash_check_dlercloud"] == "1"){
				document.getElementById("show_btn10").style.display=""	
			}else{
				document.getElementById("show_btn10").style.display="none"
			}
			if(db_merlinclash["merlinclash_check_aclrule"] == "1"){
				document.getElementById("show_btn2").style.display=""	
			}else{
				document.getElementById("show_btn2").style.display="none"	
			}
			if(db_merlinclash["merlinclash_check_controllist"] == "1"){
				document.getElementById("show_btn9").style.display=""	
			}else{
				document.getElementById("show_btn9").style.display="none"	
			}
			if(db_merlinclash["merlinclash_check_unblock"] == "1"){
				document.getElementById("show_btn8").style.display=""	
			}else{
				document.getElementById("show_btn8").style.display="none"	
			}
			if(db_merlinclash["merlinclash_check_kp"] == "1"){
				document.getElementById("show_btn5").style.display=""
			}else{
				document.getElementById("show_btn5").style.display="none"	
			}
			if(db_merlinclash["merlinclash_check_cdns"] == "1"){
				document.getElementById("clash_dns_area").style.display=""
			}else{
				document.getElementById("clash_dns_area").style.display="none"	
			}
			if(db_merlinclash["merlinclash_check_scriptedit"] == "1"){
				document.getElementById("clash_script_area").style.display=""
			}else{
				document.getElementById("clash_script_area").style.display="none"	
			}
			if(db_merlinclash["merlinclash_check_chost"] == "1"){
				document.getElementById("clash_host_area").style.display=""
			}else{
				document.getElementById("clash_host_area").style.display="none"	
			}
			if(db_merlinclash["merlinclash_check_kcp"] == "1"){
				document.getElementById("clash_kcp_area").style.display=""
			}else{
				document.getElementById("clash_kcp_area").style.display="none"	
			}
			if(db_merlinclash["merlinclash_check_cusport"] == "1"){
				document.getElementById("clash_cusport_area").style.display=""
			}else{
				document.getElementById("clash_cusport_area").style.display="none"	
			}
			if(db_merlinclash["merlinclash_check_clashimport"] == "1"){
				document.getElementById("clashimport").style.display=""
			}else{
				document.getElementById("clashimport").style.display="none"	
			}
			if(db_merlinclash["merlinclash_check_xiaobai"] == "1"){
				document.getElementById("xiaobai").style.display=""
			}else{
				document.getElementById("xiaobai").style.display="none"	
			}
			if(db_merlinclash["merlinclash_check_sclocal"] == "1"){
				document.getElementById("subconverterlocal").style.display=""
			}else{
				document.getElementById("subconverterlocal").style.display="none"	
			}
			if(db_merlinclash["merlinclash_check_yamldown"] == "1"){
				document.getElementById("clashyamldown").style.display=""
			}else{
				document.getElementById("clashyamldown").style.display="none"	
			}
			if(db_merlinclash["merlinclash_check_ssimport"] == "1"){
				document.getElementById("ssimport").style.display=""
			}else{
				document.getElementById("ssimport").style.display="none"	
			}
			if(db_merlinclash["merlinclash_flag"] == "HND"){
				if(db_merlinclash["merlinclash_check_upcusrule"] == "1"){
					document.getElementById("uploadcustomrule").style.display=""
				}else{
					document.getElementById("uploadcustomrule").style.display="none"	
				}
			}else{
				document.getElementById("uploadcustomrule").style.display="none"	
			}
			if(db_merlinclash["merlinclash_check_noipt"] == "1"){
				document.getElementById("noipt").style.display=""
			}else{
				document.getElementById("noipt").style.display="none"	
			}
			if(db_merlinclash["merlinclash_check_tproxy"] == "1"){
				document.getElementById("tproxy").style.display=""
			}else{
				document.getElementById("tproxy").style.display="none"	
			}
			if(db_merlinclash["merlinclash_flag"] == "HND"){
				document.getElementById("upcusrule").style.display=""
			}else{
				document.getElementById("upcusrule").style.display="none"
				document.getElementById("upcusrulecbox").style.display="none"
			}
			if(db_merlinclash["merlinclash_flag"] == "HND"){
				document.getElementById("up_scrule").style.display=""
			}else{
				document.getElementById("up_scrule").style.display="none"
			}
			if(db_merlinclash["merlinclash_flag"] == "HND"){
				document.getElementById("sc3in1").style.display=""
			}else{
				document.getElementById("sc3in1").style.display="none"
			}
			
			
			//-----------------------------------------网易云定时重启--------------------------------------//
			var sj=db_merlinclash["merlinclash_select_job"];
			$("#merlinclash_select_job").find("option[value ='"+sj+"']").attr("selected","selected");	

			var sd=db_merlinclash["merlinclash_select_day"];
			$("#merlinclash_select_day").find("option[value ='"+sd+"']").attr("selected","selected");	

			var sw=db_merlinclash["merlinclash_select_week"];
			$("#merlinclash_select_week").find("option[value ='"+sw+"']").attr("selected","selected");	

			var sh=db_merlinclash["merlinclash_select_hour"];
			$("#merlinclash_select_hour").find("option[value ='"+sh+"']").attr("selected","selected");	

			var sm=db_merlinclash["merlinclash_select_minute"];
			$("#merlinclash_select_minute").find("option[value ='"+sm+"']").attr("selected","selected");
			//-----------------------------------------定时订阅--------------------------------------//
			var srs=db_merlinclash["merlinclash_select_regular_subscribe"];
			$("#merlinclash_select_regular_subscribe").find("option[value ='"+srs+"']").attr("selected","selected");	

			var srd=db_merlinclash["merlinclash_select_regular_day"];
			$("#merlinclash_select_regular_day").find("option[value ='"+srd+"']").attr("selected","selected");	

			var srw=db_merlinclash["merlinclash_select_regular_week"];
			$("#merlinclash_select_regular_week").find("option[value ='"+srw+"']").attr("selected","selected");	

			var srh=db_merlinclash["merlinclash_select_regular_hour"];
			$("#merlinclash_select_regular_hour").find("option[value ='"+srh+"']").attr("selected","selected");	

			var srm=db_merlinclash["merlinclash_select_regular_minute"];
			$("#merlinclash_select_regular_minute").find("option[value ='"+srm+"']").attr("selected","selected");
			
			var srm2=db_merlinclash["merlinclash_select_regular_minute_2"];
			$("#merlinclash_select_regular_minute_2").find("option[value ='"+srm2+"']").attr("selected","selected");
			//-----------------------------------------定时重启--------------------------------------//
			var scr=db_merlinclash["merlinclash_select_clash_restart"];
			$("#merlinclash_select_clash_restart").find("option[value ='"+scr+"']").attr("selected","selected");	

			var scrd=db_merlinclash["merlinclash_select_clash_restart_day"];
			$("#merlinclash_select_clash_restart_day").find("option[value ='"+scrd+"']").attr("selected","selected");	

			var scrw=db_merlinclash["merlinclash_select_clash_restart_week"];
			$("#merlinclash_select_clash_restart_week").find("option[value ='"+scrw+"']").attr("selected","selected");	

			var scrh=db_merlinclash["merlinclash_select_clash_restart_hour"];
			$("#merlinclash_select_clash_restart_hour").find("option[value ='"+scrh+"']").attr("selected","selected");	

			var scrm=db_merlinclash["merlinclash_select_clash_restart_minute"];
			$("#merlinclash_select_clash_restart_minute").find("option[value ='"+scrm+"']").attr("selected","selected");
			
			var scrm2=db_merlinclash["merlinclash_select_clash_restart_minute_2"];
			$("#merlinclash_select_clash_restart_minute_2").find("option[value ='"+scrm2+"']").attr("selected","selected");
			
			//GEOIP选项
			var geo=db_merlinclash["merlinclash_geoip_type"];
			$("#merlinclash_geoip_type").find("option[value ='"+geo+"']").attr("selected","selected");	

			

		}
	});
}
function conf2obj(){
	var params = ["merlinclash_koolproxy_mode", "merlinclash_koolproxy_reboot", "merlinclash_koolproxy_reboot_hour", "merlinclash_koolproxy_reboot_min", "merlinclash_koolproxy_reboot_inter_hour", "merlinclash_koolproxy_reboot_inter_min", "merlinclash_koolproxy_acl_method"];
	var params_chk = ["merlinclash_koolproxy_enable", "merlinclash_koolproxy_rule_enable_d1", "merlinclash_koolproxy_rule_enable_d2", "merlinclash_koolproxy_rule_enable_d3", "merlinclash_koolproxy_rule_enable_d4"];
	for (var i = 0; i < params.length; i++) {
		if(db_merlinclash[params_chk[i]]){
			E(params_chk[i]).checked = db_merlinclash[params_chk[i]] == "1";
		}
	}
	for (var i = 0; i < params.length; i++) {
		if(db_merlinclash[params[i]]){
			E(params[i]).value = db_merlinclash[params[i]];
		}
	}
	}
var yamlsel_tmp2;
function iptquickly_restart() {
	if(!$.trim($('#merlinclash_yamlsel').val())){
		alert("必须选择一个配置文件！");
		return false;
	}
	db_merlinclash["merlinclash_action"] = 35;
	push_data("clash_config.sh", "iptquicklyrestart",  db_merlinclash);
}
function selectlist_rebuild() {
	db_merlinclash["merlinclash_action"] = 34;
	push_data("clash_rebuild.sh", "rebuild",  db_merlinclash);
}
function quickly_restart() {
	if(!$.trim($('#merlinclash_yamlsel').val())){
		alert("必须选择一个配置文件！");
		return false;
	}
	yamlsel_tmp1 = E("merlinclash_yamlsel").value;
	var act;
	db_merlinclash["merlinclash_action"] = "1";
	var id = parseInt(Math.random() * 100000000);
	var postData = {"id": id, "method": "clash_yamltmp.sh", "params":[], "fields": ""};
	$.ajax({
		type: "POST",
		url: "/_api/",
		async: true,
		data: JSON.stringify(postData),
		success: function(response) {
			var arr = response.result.split("@");			
			yamlsel_tmp2 = arr[0];
			push_data("clash_config.sh", "quicklyrestart",  db_merlinclash);		
		}
	});	
	
}
function apply() {
	if(!$.trim($('#merlinclash_yamlsel').val())){
		alert("必须选择一个配置文件！");
		return false;
	}
	if(!$.trim($('#merlinclash_watchdog_delay_time').val())){
		alert("看门狗检查间隔时间不能为空！");
		return false;
	}
	var host_content = E("merlinclash_host_content1").value;
	var script_content = E("merlinclash_script_edit_content1").value;
	if(host_content != ""){
		if(host_content.search(/^hosts:/) >= 0){
			
		}else{
			alert("读取host区域内容有误，网页服务可能已崩溃，F5刷新页面重试");
			return false;
		} 
	}
	if(script_content != ""){
		if(script_content.search(/^script:/) >= 0){
			
		}else{
			alert("读取script区域内容有误，网页服务可能已崩溃，F5刷新页面重试");
			return false;
		} 
	}
	if(!$.trim($('#merlinclash_hostsel').val())){
		alert("HOST文件选项值丢失！请刷新页面检查！！！");
		return false;
	}else{
		db_merlinclash["merlinclash_hostsel"] = E("merlinclash_hostsel").value;
		db_merlinclash["merlinclash_hostsel_tmp"] = (E("merlinclash_hostsel").value);
	}

	var radio = document.getElementsByName("dnsplan").innerHTML = getradioval(1);
	var clashmodesel = document.getElementsByName("clashmode").innerHTML = getradioval(3);
	if(db_merlinclash["merlinclash_linuxver"] >= 41){
		var tproxymodesel = document.getElementsByName("tproxymode").innerHTML = getradioval(4);
	}
	var iptablessel = document.getElementsByName("iptablessel").innerHTML = getradioval(5);
	var unplan = document.getElementsByName("unblockplan").innerHTML = getradioval(6);
	var dnshijacksel = document.getElementsByName("dnshijack").innerHTML = getradioval(7);
	db_merlinclash["merlinclash_enable"] = E("merlinclash_enable").checked ? '1' : '0';
	db_merlinclash["merlinclash_watchdog"] = E("merlinclash_watchdog").checked ? '1' : '0';
	db_merlinclash["merlinclash_kcpswitch"] = E("merlinclash_kcpswitch").checked ? '1' : '0';
	if(db_merlinclash["merlinclash_linuxver"] >= 41){
		db_merlinclash["merlinclash_ipv6switch"] = E("merlinclash_ipv6switch").checked ? '1' : '0';
	}
	db_merlinclash["merlinclash_cirswitch"] = E("merlinclash_cirswitch").checked ? '1' : '0';
	db_merlinclash["merlinclash_startlog"] = E("merlinclash_startlog").checked ? '1' : '0'; //启动简化日志
	db_merlinclash["merlinclash_dnsgoclash"] = E("merlinclash_dnsgoclash").checked ? '1' : '0';
	db_merlinclash["merlinclash_dnsclear"] = E("merlinclash_dnsclear").checked ? '1' : '0';
	db_merlinclash["merlinclash_closeproxy"] = E("merlinclash_closeproxy").checked ? '1' : '0';
	db_merlinclash["merlinclash_passkpswitch"] = E("merlinclash_passkpswitch").checked ? '1' : '0';
	//db_merlinclash["merlinclash_check_dlercloud"] = E("merlinclash_check_dlercloud").checked ? '1' : '0';
	db_merlinclash["merlinclash_dashboardswitch"] = E("merlinclash_dashboardswitch").checked ? '1' : '0';
	db_merlinclash["merlinclash_googlehomeswitch"] = E("merlinclash_googlehomeswitch").checked ? '1' : '0';
	if(E("merlinclash_dashboardswitch").checked){
		if(!$.trim($('#merlinclash_dashboard_secret').val())){
			alert("公网访问面板开启，密码不能为空！");
			return false;
		}
	}
	db_merlinclash["merlinclash_dashboard_secret"] = E("merlinclash_dashboard_secret").value;
	db_merlinclash["merlinclash_unblockmusic_enable"] = E("merlinclash_unblockmusic_enable").checked ? '1' : '0';
	db_merlinclash["merlinclash_unblockmusic_endpoint"] = E("merlinclash_unblockmusic_endpoint").value;
	db_merlinclash["merlinclash_unblockmusic_musicapptype"] = E("merlinclash_unblockmusic_musicapptype").value;
	if(init_unblockcount == 1){
		db_merlinclash["merlinclash_unblockmusic_acl_default"] = E("merlinclash_unblockmusic_acl_default").value;
	}
	if(parseInt(db_merlinclash["merlinclash_UnblockNeteaseMusic_version"]) >= parseInt("0.2.5")){
		if(!$.trim($('#merlinclash_unblockmusic_platforms_numbers').val())){
			alert("搜索结果值不能为空！");
			return false;
		}
		db_merlinclash["merlinclash_unblockmusic_platforms_numbers"] = E("merlinclash_unblockmusic_platforms_numbers").value;
	}
	db_merlinclash["merlinclash_dnsplan"] = radio;
	db_merlinclash["merlinclash_clashmode"] = clashmodesel;
	if(db_merlinclash["merlinclash_linuxver"] >= 41){
		db_merlinclash["merlinclash_tproxymode"] = tproxymodesel;
	}else{
		db_merlinclash["merlinclash_tproxymode"] = "closed";
	}
	db_merlinclash["merlinclash_iptablessel"] = iptablessel;
	db_merlinclash["merlinclash_dnshijack"] = dnshijacksel;
	db_merlinclash["merlinclash_unblockmusic_unblockplan"] = unplan;
	db_merlinclash["merlinclash_links"] = Base64.encode(E("merlinclash_links").value);

	var links2 = Base64.encode(encodeURIComponent(E("merlinclash_links2").value));
	db_merlinclash["merlinclash_links2"] = links2;
	//URL编码后再传入后端
	var links3 = Base64.encode(encodeURIComponent(E("merlinclash_links3").value));
	db_merlinclash["merlinclash_links3"] = links3;
	db_merlinclash["merlinclash_unblockmusic_bestquality"] = E("merlinclash_unblockmusic_bestquality").checked ? '1' : '0';
	db_merlinclash["merlinclash_unblockmusic_log"] = E("merlinclash_unblockmusic_log").checked ? '1' : '0';
	db_merlinclash["merlinclash_unblockmusic_vip"] = E("merlinclash_unblockmusic_vip").checked ? '1' : '0';
	//20200828+
	db_merlinclash["merlinclash_check_delay_cbox"] = E("merlinclash_check_delay_cbox").checked ? '1' : '0';
	db_merlinclash["merlinclash_auto_delay_cbox"] = E("merlinclash_auto_delay_cbox").checked ? '1' : '0';
	if(db_merlinclash["merlinclash_flag"] == "HND"){
		db_merlinclash["merlinclash_customrule_cbox"] = E("merlinclash_customrule_cbox").checked ? '1' : '0';
	}else{
		db_merlinclash["merlinclash_cdn_cbox"] = E("merlinclash_cdn_cbox").checked ? '1' : '0';
	}
	db_merlinclash["merlinclash_custom_cbox"] = E("merlinclash_custom_cbox").checked ? '1' : '0';
	db_merlinclash["merlinclash_urltestTolerance_cbox"] = E("merlinclash_urltestTolerance_cbox").checked ? '1' : '0';
	db_merlinclash["merlinclash_interval_cbox"] = E("merlinclash_interval_cbox").checked ? '1' : '0';
	if(E("merlinclash_check_delay_cbox").checked){
		if(!$.trim($('#merlinclash_check_delay_time').val())){
			alert("检查日志延迟功能开启，秒数不能为空！");
			return false;
		}
	}
	if(E("merlinclash_auto_delay_cbox").checked){
		if(!$.trim($('#merlinclash_auto_delay_time').val())){
			alert("开机自启推迟功能开启，秒数不能为空！");
			return false;
		}
	}
	if(E("merlinclash_custom_cbox").checked){
		if(!$.trim($('#merlinclash_cus_port').val())){
			alert("自定义端口功能开启，port不能为空！");
			return false;
		}
		if(!$.trim($('#merlinclash_cus_socksport').val())){
			alert("自定义端口功能开启，socks-port不能为空！");
			return false;
		}
		if(!$.trim($('#merlinclash_cus_redirsport').val())){
			alert("自定义端口功能开启，redir-port不能为空！");
			return false;
		}
		if(!$.trim($('#merlinclash_cus_tproxyport').val())){
			alert("自定义端口功能开启，tproxy-port不能为空！");
			return false;
		}
		if(!$.trim($('#merlinclash_cus_dnslistenport').val())){
			alert("自定义端口功能开启，dns监听端口不能为空！");
			return false;
		}
		if(!$.trim($('#merlinclash_cus_dashboardport').val())){
			alert("自定义端口功能开启，面板访问端口不能为空！");
			return false;
		}
	}
	db_merlinclash["merlinclash_cus_port"] = E("merlinclash_cus_port").value;
	db_merlinclash["merlinclash_cus_socksport"] = E("merlinclash_cus_socksport").value;
	db_merlinclash["merlinclash_cus_redirsport"] = E("merlinclash_cus_redirsport").value;
	db_merlinclash["merlinclash_cus_tproxyport"] = E("merlinclash_cus_tproxyport").value;
	db_merlinclash["merlinclash_cus_dnslistenport"] = E("merlinclash_cus_dnslistenport").value;
	db_merlinclash["merlinclash_cus_dashboardport"] = E("merlinclash_cus_dashboardport").value;
	db_merlinclash["merlinclash_check_delay_time"] = E("merlinclash_check_delay_time").value;
	db_merlinclash["merlinclash_auto_delay_time"] = E("merlinclash_auto_delay_time").value;
	db_merlinclash["merlinclash_watchdog_delay_time"] = E("merlinclash_watchdog_delay_time").value;
	//20200828-
	db_merlinclash["merlinclash_yamlsel"] = E("merlinclash_yamlsel").value;
	yamlsel_tmp1 = E("merlinclash_yamlsel").value;
	db_merlinclash["merlinclash_delyamlsel"] = E("merlinclash_delyamlsel").value;
	//20200630+++
	db_merlinclash["merlinclash_acl4ssrsel"] = E("merlinclash_acl4ssrsel").value;
	//20200630---	
	db_merlinclash["merlinclash_clashtarget"] = E("merlinclash_clashtarget").value;
	db_merlinclash["merlinclash_urltestTolerancesel"] = E("merlinclash_urltestTolerancesel").value;
	db_merlinclash["merlinclash_intervalsel"] = E("merlinclash_intervalsel").value;
	if(init_nokpaclcount == 1){
		db_merlinclash["merlinclash_nokpacl_default_mode"] = E("merlinclash_nokpacl_default_mode").value;
		db_merlinclash["merlinclash_nokpacl_default_port"] = E("merlinclash_nokpacl_default_port").value;
	}

	//自定规则
	if(E("ACL_table")){
		var tr = E("ACL_table").getElementsByTagName("tr");
		//for (var i = 1; i < tr.length - 1; i++) {
		for (var i = 1; i < tr.length ; i++) {	
			var rowid = tr[i].getAttribute("id").split("_")[2];
			if (E("merlinclash_acl_type_" + i)){
				db_merlinclash["merlinclash_acl_type_" + rowid] = E("merlinclash_acl_type_" + rowid).value;
				db_merlinclash["merlinclash_acl_content_" + rowid] = E("merlinclash_acl_content_" + rowid).value;
				db_merlinclash["merlinclash_acl_lianjie_" + rowid] = E("merlinclash_acl_lianjie_" + rowid).value;					
			}else{
				
			}				
		}
	}else{
		
	}
	
	//KCP
	if(E("KCP_table")){
		var tr = E("KCP_table").getElementsByTagName("tr");
		for (var i = 1; i < tr.length ; i++) {	
			var rowid = tr[i].getAttribute("id").split("_")[2];
			if (E("merlinclash_kcp_lport_" + i)){
				db_merlinclash["merlinclash_kcp_lport_" + rowid] = E("merlinclash_kcp_lport_" + rowid).value;
				db_merlinclash["merlinclash_kcp_server_" + rowid] = E("merlinclash_kcp_server_" + rowid).value;
				db_merlinclash["merlinclash_kcp_port_" + rowid] = E("merlinclash_kcp_port_" + rowid).value;
				db_merlinclash["merlinclash_kcp_param_" + rowid] = E("merlinclash_kcp_param_" + rowid).value;
			}else{
				
			}				
		}
	}else{

	}
	//koolproxy访问控制更新
	if(E("noKPACL_table")){
		var tr = E("noKPACL_table").getElementsByTagName("tr");
		for (var i = 1; i < tr.length-1 ; i++) {	
			var rowid2 = tr[i].getAttribute("id").split("_")[2];
			//console.log(rowid2);
			if (E("merlinclash_nokpacl_name_" + rowid2)){
				db_merlinclash["merlinclash_nokpacl_name_" + rowid2] = E("merlinclash_nokpacl_name_" + rowid2).value;
				db_merlinclash["merlinclash_nokpacl_mac_" + rowid2] = E("merlinclash_nokpacl_mac_" + rowid2).value;
				db_merlinclash["merlinclash_nokpacl_mode_" + rowid2] = E("merlinclash_nokpacl_mode_" + rowid2).value;
				db_merlinclash["merlinclash_nokpacl_port_" + rowid2] = E("merlinclash_nokpacl_port_" + rowid2).value;
			}else{
				
			}				
		}
	}else{

	}
	if(E("UNMACL_table")){
		var tr = E("UNMACL_table").getElementsByTagName("tr");
		for (var i = 1; i < tr.length-1 ; i++) {	
			var rowid3 = tr[i].getAttribute("id").split("_")[2];
			//console.log(rowid3);
			if (E("merlinclash_unblockmusic_acl_mode_" + rowid3)){
				if(E("merlinclash_unblockmusic_acl_ip_" + rowid3).value != ""){
					db_merlinclash["merlinclash_unblockmusic_acl_ip_" + rowid3] = E("merlinclash_unblockmusic_acl_ip_" + rowid3).value;
				}else{
					db_merlinclash["merlinclash_unblockmusic_acl_ip_" + rowid3] = " ";
				}
				if(E("merlinclash_unblockmusic_acl_mac_" + rowid3).value != ""){
					db_merlinclash["merlinclash_unblockmusic_acl_mac_" + rowid3] = E("merlinclash_unblockmusic_acl_mac_" + rowid3).value;
				}else{
					db_merlinclash["merlinclash_unblockmusic_acl_mac_" + rowid3] = " ";
				}
				db_merlinclash["merlinclash_unblockmusic_acl_name_" + rowid3] = E("merlinclash_unblockmusic_acl_name_" + rowid3).value;
				db_merlinclash["merlinclash_unblockmusic_acl_mode_" + rowid3] = E("merlinclash_unblockmusic_acl_mode_" + rowid3).value;
			}else{
				
			}				
		}
	}else{

	}
	var act;
	if(E("merlinclash_enable").checked){ 
			db_merlinclash["merlinclash_action"] = "1";
	}else{
			db_merlinclash["merlinclash_action"] = "0";
	}
	//-----------koolproxy启动参数---------------//
	console.log(init_kpcount2);
	
	if(init_kpcount2 == 1){
		var params = ["merlinclash_koolproxy_mode", "merlinclash_koolproxy_reboot", "merlinclash_koolproxy_reboot_hour", "merlinclash_koolproxy_reboot_min", "merlinclash_koolproxy_reboot_inter_hour", "merlinclash_koolproxy_reboot_inter_min", "merlinclash_koolproxy_acl_method", "merlinclash_koolproxy_acl_default"];
		var params_chk = ["merlinclash_koolproxy_enable", "merlinclash_koolproxy_rule_enable_d1", "merlinclash_koolproxy_rule_enable_d2", "merlinclash_koolproxy_rule_enable_d3", "merlinclash_koolproxy_rule_enable_d4"];
		for (var i = 0; i < params.length; i++) {
			db_merlinclash[params[i]] = E(params[i]).value;
		}
		for (var i = 0; i < params_chk.length; i++) {
			db_merlinclash[params_chk[i]] = E(params_chk[i]).checked ? "1" : "0";
		}
		//增加KP开关屏蔽
		//db_merlinclash["merlinclash_koolproxy_enable"] = E["merlinclash_koolproxy_enable"] == "0";
		// collect value in user rule textarea
		db_merlinclash["merlinclash_koolproxy_custom_rule"] = Base64.encode(E("usertxt").value);
		// collect data from acl pannel
		//maxid = parseInt($("#KPYACL_table > tbody > tr:eq(-2) > td:nth-child(1) > input").attr("id").split("_")[3]);
	}

	if(E("KPYACL_table")){
		var tr = E("KPYACL_table").getElementsByTagName("tr");
		for (var i = 1; i < tr.length ; i++) {	
			if (E("merlinclash_koolproxy_acl_mode_" + i)){
				if(E("merlinclash_koolproxy_acl_ip_" + i).value != ""){
					db_merlinclash["merlinclash_koolproxy_acl_ip_" + i] = E("merlinclash_koolproxy_acl_ip_" + i).value;
				}else{
					db_merlinclash["merlinclash_koolproxy_acl_ip_" + i] = " ";
				}
				if(E("merlinclash_koolproxy_acl_mac_" + i).value != ""){
					db_merlinclash["merlinclash_koolproxy_acl_mac_" + i] = E("merlinclash_koolproxy_acl_mac_" + i).value;
				}else{
					db_merlinclash["merlinclash_koolproxy_acl_mac_" + i] = " ";
				}
				db_merlinclash["merlinclash_koolproxy_acl_name_" + i] = E("merlinclash_koolproxy_acl_name_" + i).value;
				db_merlinclash["merlinclash_koolproxy_acl_mode_" + i] = E("merlinclash_koolproxy_acl_mode_" + i).value;
			}else{
				
			}				
		}
	}else{

	}
	// collect data from rule pannel
	if(E("rule_table")){
		var tr = E("rule_table").getElementsByTagName("tr");
		for (var i = 1; i < tr.length ; i++) {	
			if (E("merlinclash_koolproxy_rule_enable_" + i)){
				db_merlinclash["merlinclash_koolproxy_rule_enable_" + i] = E("merlinclash_koolproxy_rule_enable_" + i).checked ? "1" : "0";
			}else{
				
			}				
		}
	}else{

	}
	var sourceList="";
	if(E("merlinclash_koolproxy_rule_enable_d1").checked == true){
		sourceList += "1|koolproxy.txt||静态规则>"
	}else{
		sourceList += "0|koolproxy.txt||静态规则>"
	}
	if(E("merlinclash_koolproxy_rule_enable_d2").checked == true){
		sourceList += "1|daily.txt||每日规则>"
	}else{
		sourceList += "0|daily.txt||每日规则>"
	}
	if(E("merlinclash_koolproxy_rule_enable_d3").checked == true){
		sourceList += "1|kp.dat||视频规则>"
	}else{
		sourceList += "0|kp.dat||视频规则>"
	}
	if(E("merlinclash_koolproxy_rule_enable_d4").checked == true){
		sourceList += "1|user.txt||自定规则>"
	}else{
		sourceList += "0|user.txt||自定规则>"
	}
	//maxid = parseInt($("#rule_table > tbody > tr:eq(-2) > td:nth-child(1) > input").attr("id").split("_")[3]);
	var maxid = E("rule_table").getElementsByTagName("tr");
	for ( var i = 1; i <= maxid.length; ++i ) {
		if (E("merlinclash_koolproxy_rule_enable_" + i)){
			sourceList += E("merlinclash_koolproxy_rule_enable_" + i).checked ? "1" : "0";
			sourceList += "|"
			sourceList += E("merlinclash_koolproxy_rule_file_" + i).innerHTML
			sourceList += "|"
			sourceList += E("merlinclash_koolproxy_rule_addr_" + i).innerHTML
			sourceList += "|"
			sourceList += E("merlinclash_koolproxy_rule_note_" + i).innerHTML
			sourceList += ">"
		}
	}
	db_merlinclash["merlinclash_koolproxy_sourcelist"] = sourceList;
	//------------------------------------------//
	var id = parseInt(Math.random() * 100000000);
	var postData = {"id": id, "method": "clash_yamltmp.sh", "params":[], "fields": ""};
	$.ajax({
		type: "POST",
		url: "/_api/",
		async: true,
		data: JSON.stringify(postData),
		success: function(response) {
			var arr = response.result.split("@");
				yamlsel_tmp2 = arr[0];
				//更换配置文件，清空节点指定内容
				if(yamlsel_tmp2==null){
					yamlsel_tmp2=yamlsel_tmp1				
				}
				if(yamlsel_tmp2!=yamlsel_tmp1){
					db_merlinclash["merlinclash_action"] = "1";
					db_merlinclash["merlinclash_yamlselchange"] = "1";
					//更换配置将模式重置为default 20201208
					db_merlinclash["merlinclash_clashmode"] = "default";
				}
				if(yamlsel_tmp2 == yamlsel_tmp1){
					db_merlinclash["merlinclash_action"] = "1";
					db_merlinclash["merlinclash_yamlselchange"] = "0";
				}
				push_data("clash_config.sh", "start",  db_merlinclash);
			
		},
		error: function(){
			console.log("ERROR");
		}
	});

	
}
//push_data方法。调用实时日志显示
function push_data(script, arg, obj, flag){
	if (!flag) showMCLoadingBar();
	var id = parseInt(Math.random() * 100000000);
	var postData = {"id": id, "method": script, "params":[arg], "fields": obj};
	$.ajax({
		type: "POST",
		cache:false,
		url: "/_api/",
		data: JSON.stringify(postData),
		dataType: "json",
		success: function(response){
			if(response.result == id){
				if(flag && flag == "1"){
					refreshpage();
				}else if(flag && flag == "2"){
					//continue;
					//do nothing
				}else{
					if(db_merlinclash["merlinclash_startlog"] == "1" && script == "clash_config.sh" && arg == "start"){
						get_realtime_log_sim();
					}else{
						get_realtime_log();
					}
					
				}
			}
		}
	});
}
function tabSelect(w) {
	trig=".show-btn" + w;
	for (var i = 0; i <= 10; i++) {
		$('.show-btn' + i).removeClass('active');
		$('#tablet_' + i).hide();
	}
	$('.show-btn' + w).addClass('active');
	$('#tablet_' + w).show();

	var id = parseInt(Math.random() * 100000000);
	var dbus_post={};
	dbus_post["merlinclash_trigger"] = db_merlinclash["merlinclash_trigger"] = trig;
	var postData = {"id": id, "method": "dummy_script.sh", "params":[], "fields": dbus_post};
	$.ajax({
		type: "POST",
		cache:false,
		url: "/_api/",
		data: JSON.stringify(postData),
		dataType: "json",
		success: function(response) {
			
		}
	});

}
function dingyue() {
	var trig = ".show-btn1"	
	$(trig).trigger("click");
}
function generate_options(){
	for(var i = 0; i < 24; i++) {
		$("#merlinclash_koolproxy_reboot_hour").append("<option value='"  + i + "'>" + i + "点</option>");
		$("#merlinclash_koolproxy_reboot_inter_hour").append("<option value='"  + i + "'>" + i + "时</option>");
	}
	for(var i = 0; i < 60; i++) {
		$("#merlinclash_koolproxy_reboot_min").append("<option value='"  + i + "'>" + i + "分</option>");
		$("#merlinclash_koolproxy_reboot_inter_min").append("<option value='"  + i + "'>" + i + "分</option>");
	}
}
function hook_event(){
	$("#log_content2").click(
		function() {
		x = -10;
	});
	$("#merlinclash_koolproxy_download_cert").click(
	function() {
		location.href = "http://110.110.110.110";
	});
	$("#merlinclash_koolproxy_enable").click(
		function(){
		if(E('merlinclash_koolproxy_enable').checked){
			db_merlinclash["merlinclash_koolproxy_enable"] = "1";
			db_merlinclash["merlinclash_koolproxy_basic_action"] = "1";
		}else{
			db_merlinclash["merlinclash_koolproxy_enable"] = "0";
			db_merlinclash["merlinclash_koolproxy_basic_action"] = "0";
		}
	});
}
function update_visibility(r){
	
	showhide("merlinclash_koolproxy_reboot_hour_span", (E("merlinclash_koolproxy_reboot").value == 1));
	showhide("merlinclash_koolproxy_reboot_interval_span", (E("merlinclash_koolproxy_reboot").value == 2));
	var maxrule = parseInt($("#rule_table > tbody > tr:eq(-2) > td:nth-child(1) > input").attr("id").split("_")[3]);
	if($(r).attr("id") == "merlinclash_koolproxy_mode"){
		if(E("merlinclash_koolproxy_mode").value == 3){
			E("merlinclash_koolproxy_rule_enable_d1").checked = false;
			E("merlinclash_koolproxy_rule_enable_d2").checked = false;
			E("merlinclash_koolproxy_rule_enable_d3").checked = true;
			E("merlinclash_koolproxy_rule_enable_d4").checked = false;
			for ( var i = 1; i <= maxrule; ++i ) {
				if (E("merlinclash_koolproxy_rule_enable_" + i)){
					E("merlinclash_koolproxy_rule_enable_" + i).checked = false;
				}
			}
		}else{
			E("merlinclash_koolproxy_rule_enable_d1").checked = true;
			E("merlinclash_koolproxy_rule_enable_d2").checked = true;
			E("merlinclash_koolproxy_rule_enable_d3").checked = true;
			E("merlinclash_koolproxy_rule_enable_d4").checked = true;
			for ( var i = 1; i <= maxrule; ++i ) {
				if (E("merlinclash_koolproxy_rule_enable_" + i)){
					E("merlinclash_koolproxy_rule_enable_" + i).checked = true;
				}
			}
		}
	}
}
function dnsplan() {
	var trig = ".show-btn4"	
	$(trig).trigger("click");
}
function dy_for_version(){
	if(db_merlinclash["merlinclash_flag"] == "HND"){
		E("dingyue2").innerHTML = "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;或者使用【<a style='cursor:pointer' onclick='dingyue()' href='javascript:void(0);'><em><u>SubConverter本地转换</u></em></a>】。";
		E("scoracl").innerHTML = "SubConverter本地转换";
		E("scoracl2").innerHTML = "<em style='color: gold;'>内置Acl4ssr项目规则</em>";
		E("scoracl3").innerHTML = "【S&nbsp;C&nbsp;本地转换】";
		document.getElementById("scaddr").style.display="none"
	}else{
		E("dingyue2").innerHTML = "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;或者使用【<a href='https://acl4ssr.netlify.app/' target='_blank'><em><u>ACL4SSR 在线订阅转换</u></em></a>】。";
		E("scoracl").innerHTML = "通过ACL4SSR在线转换";
		E("scoracl2").innerHTML = "<em style='color: gold;'>与GitHub项目同步更新；CDN规则可能滞后</em>";
		E("scoracl3").innerHTML = "【ACL在线转换】";
	}
}
function toggle_func() {
	//首页
	$(".show-btn0").click(
		function() {
			tabSelect(0);
			$('#apply_button').show();
			$('#delallowneracls_button').hide();		
		});
	//配置文件栏
	$(".show-btn1").click( 
		function() {
			if(dy_count == 0){
				set_rulemode();
			}
			dy_count = 1;
			tabSelect(1);
			$('#apply_button').hide(); 
			$('#delallowneracls_button').hide();
			
		});
	//自定规则栏
	$(".show-btn2").click(
		function() {
			if(init_aclcount == 0){
				refresh_acl_table();	
				script_get();
				proxygroup_select();
			}
			init_aclcount = 1;
			tabSelect(2);
			$('#apply_button').show();
			$('#delallowneracls_button').show();
		});
	//黑白郎君栏
	$(".show-btn9").click(
		function() {
			if(init_nokpaclcount == 0){
				refresh_nokpacl_table();
			}
			init_nokpaclcount = 1;
			tabSelect(9);
			$('#apply_button').show();
			$('#delallowneracls_button').hide();
		});
	//高级模式栏
	$(".show-btn3").click(
		function() {
			if(init_advancedcount == 0){
				refresh_kcp_table();
			}
			init_advancedcount = 1;
			tabSelect(3);
			$('#apply_button').show(); 
			$('#delallowneracls_button').hide();
			
		});
	//附加功能栏
	$(".show-btn4").click(
		function() {
			if(select_count == 0){
				clashbinary_select();
				get_dnsyaml(db_merlinclash["merlinclash_dnsedit_tag"]);
				get_host(db_merlinclash["merlinclash_hostsel"]);
				
			}
			select_count = 1;
			if(db_merlinclash["merlinclash_updata_date"]){
				E("geoip_updata_date").innerHTML = "<span style='color: gold'>上次更新时间："+db_merlinclash["merlinclash_updata_date"]+"</span>";
			}
			if(db_merlinclash["merlinclash_chnrouteupdate_date"]){
				E("chnroute_updata_date").innerHTML = "<span style='color: gold'>上次更新时间："+db_merlinclash["merlinclash_chnrouteupdate_date"]+"</span>";
			}
			tabSelect(4);
			$('#apply_button').show();
			$('#delallowneracls_button').hide();					
		});
	//护网大师栏
	$(".show-btn5").click(
		function() {
			if(init_kpcount2 == 0){
				//护网大师 数据交互
				conf2obj();
				//护网大师 访问控制
				refresh_kpyacl_table();
				//护网大师 规则控制
				refresh_kpyrule_table();
				//护网大师 自定规则
				get_user_rule();
				//护网大师 运行状态
				get_kprun_status_front();
				//护网大师 定时重启下拉内容
				generate_options();
				//护网大师 模式切换
				update_visibility();
				//护网大师 事件绑定
				hook_event();
				//-----------------------------------------KOOLPROXY定时重启--------------------------------------//
				var krh=db_merlinclash["merlinclash_koolproxy_reboot_hour"];
				console.log(krh);
				$("#merlinclash_koolproxy_reboot_hour").find("option[value ='"+krh+"']").attr("selected","selected");	
				var krm=db_merlinclash["merlinclash_koolproxy_reboot_min"];
				$("#merlinclash_koolproxy_reboot_min").find("option[value ='"+krm+"']").attr("selected","selected");	
				var rih=db_merlinclash["merlinclash_koolproxy_reboot_inter_hour"];
				$("#merlinclash_koolproxy_reboot_inter_hour").find("option[value ='"+rih+"']").attr("selected","selected");	
				var rim=db_merlinclash["merlinclash_koolproxy_reboot_inter_min"];
				$("#merlinclash_koolproxy_reboot_inter_min").find("option[value ='"+rim+"']").attr("selected","selected");	

			}
			init_kpcount2 = 1;
			tabSelect(5);
			$('#apply_button').show();
			$('#delallowneracls_button').hide();
			
			
		});
	//当前配置栏
	$(".show-btn6").click(
		function() {
			if(yamlview_count == 0){
				//console.log(yamlview_count);
				yaml_view();
			}
			yamlview_count = 1;
			tabSelect(6);
			$('#apply_button').hide();
			$('#delallowneracls_button').hide();
			
			
		});
	//日志记录栏
	$(".show-btn7").click(
		function() {
			if(log_count == 0){
				//console.log(log_count);
				node_remark_view();
				get_log();
			}
			log_count = 1;
			tabSelect(7);
			$('#apply_button').hide();
			$('#delallowneracls_button').hide();	
					
		});
	//云村解锁栏
    $(".show-btn8").click(
		function() {
			if(init_unblockcount == 0){
				//云村解锁
				refresh_unmacl_table();
			}
			init_unblockcount = 1;
			if(parseInt(db_merlinclash["merlinclash_UnblockNeteaseMusic_version"]) >= parseInt("0.2.5")){
				document.getElementById("merlinclash_unblockmusic_platforms_numbers").style.visibility="visible"	
			}else{
				document.getElementById("merlinclash_unblockmusic_platforms_numbers").style.visibility="hidden"	
			}
			tabSelect(8);
			$('#apply_button').show();
			$('#delallowneracls_button').hide();
								
		});
	//DC用户栏
    $(".show-btn10").click(
		function() {
			tabSelect(10);
			$('#apply_button').hide();
			$('#delallowneracls_button').hide();
		});
	//显示默认页
	if(db_merlinclash["merlinclash_trigger"]){
		var trig= db_merlinclash["merlinclash_trigger"];
	}else{
		var trig = ".show-btn0"
	}
	
	$(trig).trigger("click");

}
function get_kprun_status_front(){
	//var maxid = parseInt($("#rule_table > tbody > tr:eq(-2) > td:nth-child(1) > input").attr("id").split("_")[3]);
	//console.log(init_kpcount);
	if(init_kpcount==0){
		var maxid = E("rule_table").getElementsByTagName("tr");
		//console.log(maxid);
		var id = parseInt(Math.random() * 100000000);
		var postData = {"id": id, "method": "clash_KoolProxy_status.sh", "params":[2], "fields": ""};
		$.ajax({
			type: "POST",
			cache:false,
			url: "/_api/",
			data: JSON.stringify(postData),
			dataType: "json",
			success: function(response){
				E("merlinclash_koolproxy_status").innerHTML = response.result.split("@@")[0];
				$("#kp_rule_1").html(response.result.split("@@")[1])
				$("#kp_rule_2").html(response.result.split("@@")[2])
				$("#kp_rule_3").html(response.result.split("@@")[3])
				$("#kp_rule_4").html(response.result.split("@@")[4])
				for ( var i = 5; i < response.result.split("@@").length; i++) {
					var va = response.result.split("@@")[i].split("&&")[0];
					var nu = response.result.split("@@")[i].split("&&")[1];
					if (E("merlinclash_koolproxy_rule_nu_" + parseInt(nu))){
						$("#merlinclash_koolproxy_rule_nu_" + parseInt(nu)).html(va);
					}
				}
				init_kpcount = 1;
				setTimeout("get_kprun_status_front();", 5000);
			},
			error: function(){
				E("merlinclash_koolproxy_status").innerHTML = "获取运行状态失败！";
				$("#kp_rule_1").html("获取规则状态失败")
				$("#kp_rule_2").html("获取规则状态失败")
				$("#kp_rule_3").html("获取规则状态失败")
				$("#kp_rule_4").html("获取规则状态失败")
				setTimeout("get_kprun_status_front();", 3000);
			}
		});
	}
}
function get_user_rule() {
	$.ajax({
		url: '/_temp/user.txt',
		type: 'GET',
		cache:false,
		dataType: 'text',
		success: function(res) {
			$('#usertxt').val(res);
		}
	});
}
function get_clash_status_front() {
	if (db_merlinclash['merlinclash_enable'] != "1") {
		E("clash_state1").innerHTML = "Clash启动时间 - " + "Waiting...";
		E("clash_state2").innerHTML = "Clash进程 - " + "Waiting...";
		E("clash_state3").innerHTML = "看门狗进程 - " + "Waiting...";
		E("dashboard_state2").innerHTML = "管理面板";
		E("dashboard_state4").innerHTML = "面板密码";
		return false;
	}
	var id = parseInt(Math.random() * 100000000);
	var postData = {"id": id, "method": "clash_status.sh", "params":[], "fields": ""};
	$.ajax({
		type: "POST",
		url: "/_api/",
		async: true,
		data: JSON.stringify(postData),
		success: function(response) {
			//console.log(init_count);
			if (init_count==0){
				var arr = response.result.split("@");
				if (arr[0] == "" || arr[1] == "") {
					E("clash_state1").innerHTML = "clash启动时间 - " + "Waiting for first refresh...";
					E("clash_state2").innerHTML = "clash进程 - " + "Waiting for first refresh...";
					E("clash_state3").innerHTML = "看门狗进程 - " + "Waiting for first refresh...";
					E("dashboard_state2").innerHTML = "管理面板";
					E("dashboard_state4").innerHTML = "面板密码";
				} else {
					E("clash_state1").innerHTML = arr[18];
					E("clash_state2").innerHTML = arr[0];
					E("clash_state3").innerHTML = arr[1];
					//$("#yacd").html("<a type='button' href='http://"+ location.hostname + ":" +arr[3]+ "/ui/yacd/index.html?hostname=" + location.hostname + "&port=" + arr[3] + "&secret=" + arr[16] +"'" + " target='_blank' >访问 YACD-Clash 面板</a>");
					//$("#razord").html("<a type='button' href='http://"+ location.hostname + ":" +arr[3]+ "/ui/razord/index.html' target='_blank' >访问 RAZORD-Clash 面板</a>");	
					E("dashboard_state2").innerHTML = arr[5];
					E("dashboard_state4").innerHTML = arr[15];
					yamlsel_tmp2 = arr[7];
					E("merlinclash_unblockmusic_version").innerHTML = arr[8];
					E("merlinclash_unblockmusic_status").innerHTML = arr[9];
					//E("proxygroup_version").innerHTML = arr[10];
					E("patch_version").innerHTML = arr[12];
					//E("patch_version2").innerHTML = arr[17];
					if(db_merlinclash["merlinclash_flag"] == "HND"){
						E("sc_version").innerHTML = arr[13];
					}
					if(db_merlinclash["merlinclash_flag"] != "OTH"){
						if ((document.domain).indexOf('.kooldns.cn') != -1 || (document.domain).indexOf('.ddnsto.com') != -1) {
							var protocol = location.protocol + "//"
							var domain = (document.domain).indexOf('.kooldns.cn') != -1 ? (location.hostname).replace('.kooldns.cn','-clash.kooldns.cn') : (location.hostname).replace('.ddnsto.com','-clash.ddnsto.com')
							$("#yacd").html("<a type='button' style='vertical-align: middle; cursor:pointer;' class='ss_btn' href='" + protocol + domain + ":" + "/ui/yacd/index.html?" + encodeURIComponent("hostname=" + protocol + domain + "&port=" + arr[3] + "&secret=" + arr[16]) +"'" + " target='_blank' >访问 YACD-Clash 面板</a>");
							$("#razord").html("<a type='button' style='vertical-align: middle; cursor:pointer;' class='ss_btn' href='" + protocol + domain + ":" + "/ui/razord/index.html' target='_blank' >访问 RAZORD-Clash 面板</a>");
							}
						else {
							$("#yacd").html("<a type='button' style='vertical-align: middle; cursor:pointer;' class='ss_btn' href='http://"+ location.hostname + ":" +arr[3]+ "/ui/yacd/index.html?hostname=" + location.hostname + "&port=" + arr[3] + "&secret=" + arr[16] +"'" + " target='_blank' >访问 YACD-Clash 面板</a>");
							$("#razord").html("<a type='button' style='vertical-align: middle; cursor:pointer;' class='ss_btn' href='http://"+ location.hostname + ":" +arr[3]+ "/ui/razord/index.html' target='_blank' >访问 RAZORD-Clash 面板</a>");  
						}
					}else{
						$("#yacd").html("<a type='button' style='vertical-align: middle; cursor:pointer;' id='yacd' class='ss_btn' href='http://yacd.haishan.me/' >访问 YACD-Clash 面板</a>");
						$("#razord").html("<a type='button' style='vertical-align: middle; cursor:pointer;' class='ss_btn' id='razord' href='http://clash.razord.top/' >访问 RAZORD-Clash 面板</a>");  
					}
					E("clash_yamlsel").innerHTML = arr[14];
				}
				init_count = 1;
			} else {
				var id2 = parseInt(Math.random() * 100000000);
				var postData = {"id": id2, "method": "clash_status2.sh", "params":[], "fields": ""};
				$.ajax({
					type: "POST",
					url: "/_api/",
					async: true,
					data: JSON.stringify(postData),
					success: function(response) {
						//console.log(init_count);
						var arr = response.result.split("@");
						//console.log(arr);
						if (arr[0] == "" || arr[1] == "") {
							E("clash_state1").innerHTML = "clash启动时间 - " + "Waiting for first refresh...";
							E("clash_state2").innerHTML = "clash进程 - " + "Waiting for first refresh...";
							E("clash_state3").innerHTML = "看门狗进程 - " + "Waiting for first refresh...";
						} else {
							E("clash_state1").innerHTML = arr[2];
							E("clash_state2").innerHTML = arr[0];
							E("clash_state3").innerHTML = arr[1];	
						}
					}
				});
			}
	setTimeout("get_clash_status_front();", 5000);
		}
	});
}
//----------------详细状态-----------------------------
function close_proc_status() {
	$("#detail_status").fadeOut(200);
}
function get_proc_status() {
	$("#detail_status").fadeIn(500);
	var id = parseInt(Math.random() * 100000000);
	var postData = {"id": id, "method": "clash_proc_status.sh", "params":[], "fields": ""};
	$.ajax({
		type: "POST",
		cache:false,
		url: "/_api/",
		data: JSON.stringify(postData),
		dataType: "json",
		success: function(response) {
			if(response.result == id){
				write_proc_status();
			}
		}
	});
}
function write_proc_status() {
	$.ajax({
		url: '/_temp/clash_proc_status.txt',
		type: 'GET',
		cache:false,
		dataType: 'text',
		success: function(res) {
			$('#proc_status').val(res);
		}
	});
}
//----------------详细状态-----------------------------
//----------------定时订阅日志-----------------------------
function close_regular_log() {
	$("#regular_log_status").fadeOut(200);
}
function get_regular_log() {
	$("#regular_log_status").fadeIn(500);
	write_regular_log();
}
function write_regular_log() {
	$.ajax({
		url: '/_temp/merlinclash_regular.log',
		type: 'GET',
		cache:false,
		dataType: 'text',
		success: function(res) {
			$('#regular_log').val(res);
		}
	});
}
//----------------定时订阅日志-----------------------------
//----------------网易云音乐解锁日志 BEGIN-----------------------
function close_unblockmusic_log() {
	$("#unblockmusic_log_status").fadeOut(200);
}
function get_unblockmusic_log() {
	$("#unblockmusic_log_status").fadeIn(500);
	write_unblockmusic_log();
}
function write_unblockmusic_log() {
	$.ajax({
		url: '/_temp/UnblockMusic.log',
		type: 'GET',
		cache:false,
		dataType: 'text',
		success: function(res) {
			$('#unblockmusic_log').val(res);
		}
	});
}
//----------------网易云音乐解锁日志 END-----------------------
//----------------DC 订阅 ------------------------------------
function dc_ss_yaml (action) {
	var dbus_post = {};
	var dcss = document.getElementById("dc_ss_1").innerHTML;
	var links_base64 = "";
	links_base64 = Base64.encode(dcss);
	dbus_post["merlinclash_links"] = links_base64;
	
	dbus_post["merlinclash_uploadrename"] = "dler_ss";
	dbus_post["merlinclash_action"] = action;
	push_data("clash_online_yaml.sh", action,  dbus_post);
		
}
function dc_v2_yaml (action) {
	var dbus_post = {};
	var dcv2 = document.getElementById("dc_v2_1").innerHTML;
	var links_base64 = "";
	links_base64 = Base64.encode(dcv2);
	dbus_post["merlinclash_links"] = links_base64;
	
	dbus_post["merlinclash_uploadrename"] = "dler_v2";
	dbus_post["merlinclash_action"] = action;
	push_data("clash_online_yaml.sh", action,  dbus_post);
		
}
function dc_tj_yaml (action) {
	var dbus_post = {};
	var dctj = document.getElementById("dc_trojan_1").innerHTML;
	var links_base64 = "";
	links_base64 = Base64.encode(dctj);
	dbus_post["merlinclash_links"] = links_base64;
	
	dbus_post["merlinclash_uploadrename"] = "dler_tj";
	dbus_post["merlinclash_action"] = action;
	push_data("clash_online_yaml.sh", action,  dbus_post);
		
}
function get_online_yaml(action) {
	var dbus_post = {};
	if(!$.trim($('#merlinclash_uploadrename').val())){
		alert("重命名框不能为空！");
		return false;
	}
	if(!$.trim($('#merlinclash_links').val())){
		alert("订阅链接不能为空！");
		return false;
	}
	var links_base64 = "";
	links_base64 = Base64.encode(E("merlinclash_links").value);
	dbus_post["merlinclash_links"] = db_merlinclash["merlinclash_links"] = links_base64;
	dbus_post["merlinclash_uploadrename"] = db_merlinclash["merlinclash_uploadrename"] = (E("merlinclash_uploadrename").value);
	dbus_post["merlinclash_action"] = db_merlinclash["merlinclash_action"] = action;
	push_data("clash_online_yaml.sh", action,  dbus_post);
	
}
function get_online_yaml2(action) {
	var dbus_post = {};
	if(!$.trim($('#merlinclash_uploadrename2').val())){
		alert("重命名框不能为空！");
		return false;
	}
	if(!$.trim($('#merlinclash_links2').val())){
		alert("订阅链接不能为空！");
		return false;
	}
	if(db_merlinclash["merlinclash_flag"] != "HND"){
		if(!$.trim($('#merlinclash_subconverter_addr').val())){
		var addr = "https://api.tshl.us/";
		}else{
			var addr =E("merlinclash_subconverter_addr").value;
		}
	}
	var links2 = Base64.encode(encodeURIComponent(E("merlinclash_links2").value));
	dbus_post["merlinclash_links2"] = db_merlinclash["merlinclash_links2"] = links2;
	dbus_post["merlinclash_uploadrename2"] = db_merlinclash["merlinclash_uploadrename2"] = (E("merlinclash_uploadrename2").value);
	if(db_merlinclash["merlinclash_flag"] != "HND"){
		dbus_post["merlinclash_subconverter_addr"] = db_merlinclash["merlinclash_subconverter_addr"] = addr;
	}
	dbus_post["merlinclash_action"] = db_merlinclash["merlinclash_action"] = action;
	push_data("clash_online_yaml_2.sh", action,  dbus_post);
	
}
function get_online_yaml3(action) {
	var dbus_post = {};
	if(!$.trim($('#merlinclash_uploadrename4').val())){
		alert("重命名框不能为空！");
		return false;
	}
	if(!$.trim($('#merlinclash_links3').val())){
		alert("订阅链接不能为空！");
		return false;
	}
	if(!$.trim($('#merlinclash_subconverter_include').val())){
		var include = "";
	}else{
		var include = encodeURIComponent(E("merlinclash_subconverter_include").value);
	}
	if(!$.trim($('#merlinclash_subconverter_exclude').val())){
		var exclude = "";
	}else{
		var exclude = encodeURIComponent(E("merlinclash_subconverter_exclude").value);
	}
	if(db_merlinclash["merlinclash_flag"] != "HND"){
		if(!$.trim($('#merlinclash_subconverter_addr').val())){
			var addr = "https://api.tshl.us/";
		}else{
			var addr =E("merlinclash_subconverter_addr").value;
		}
	}
	var links3 = Base64.encode(encodeURIComponent(E("merlinclash_links3").value));
	dbus_post["merlinclash_links3"] = db_merlinclash["merlinclash_links3"] = links3;
	dbus_post["merlinclash_uploadrename4"] = db_merlinclash["merlinclash_uploadrename4"] = (E("merlinclash_uploadrename4").value);
	dbus_post["merlinclash_action"] = db_merlinclash["merlinclash_action"] = action;
	//20200630+++
	dbus_post["merlinclash_acl4ssrsel"] = db_merlinclash["merlinclash_acl4ssrsel"] = E("merlinclash_acl4ssrsel").value;
	if(db_merlinclash["merlinclash_flag"] == "HND"){
		if(E("merlinclash_customrule_cbox").checked){
			if(!$.trim($('#merlinclash_acl4ssrsel_cus').val())){
				alert("自定订阅选项不能为空！");
				return false;
			}
			dbus_post["merlinclash_acl4ssrsel_cus"] = db_merlinclash["merlinclash_acl4ssrsel_cus"] = E("merlinclash_acl4ssrsel_cus").value;
		}
	}
	//20210916+++
	if(E("merlinclash_customurl_cbox").checked){
		if(!$.trim($('#merlinclash_uploadiniurl').val())){
			alert("远程配置地址不能为空！");
			return false;
		}
		urlbase64 = Base64.encode(encodeURIComponent(E("merlinclash_uploadiniurl").value));
		dbus_post["merlinclash_uploadiniurl"] = db_merlinclash["merlinclash_uploadiniurl"] = urlbase64;
	}
	dbus_post["merlinclash_customurl_cbox"] = db_merlinclash["merlinclash_customurl_cbox"] = E("merlinclash_customurl_cbox").checked ? '1' : '0';
	
	//20210916---
	//20200630---
	//20200804
	if(db_merlinclash["merlinclash_flag"] != "HND"){
		dbus_post["merlinclash_cdn_cbox"] = db_merlinclash["merlinclash_cdn_cbox"] = E("merlinclash_cdn_cbox").checked ? '1' : '0';
		dbus_post["merlinclash_subconverter_addr"] = db_merlinclash["merlinclash_subconverter_addr"] = addr;
	}
	dbus_post["merlinclash_clashtarget"] = db_merlinclash["merlinclash_clashtarget"] = E("merlinclash_clashtarget").value;
	dbus_post["merlinclash_subconverter_include"] = db_merlinclash["merlinclash_subconverter_include"] = include;
	dbus_post["merlinclash_subconverter_exclude"] = db_merlinclash["merlinclash_subconverter_exclude"] = exclude;
	dbus_post["merlinclash_subconverter_emoji"] = db_merlinclash["merlinclash_subconverter_emoji"] = E("merlinclash_subconverter_emoji").checked ? '1' : '0';
	dbus_post["merlinclash_subconverter_udp"] = db_merlinclash["merlinclash_subconverter_udp"] = E("merlinclash_subconverter_udp").checked ? '1' : '0';
	dbus_post["merlinclash_subconverter_append_type"] = db_merlinclash["merlinclash_subconverter_append_type"] = E("merlinclash_subconverter_append_type").checked ? '1' : '0';
	dbus_post["merlinclash_subconverter_sort"] = db_merlinclash["merlinclash_subconverter_sort"] = E("merlinclash_subconverter_sort").checked ? '1' : '0';
	dbus_post["merlinclash_subconverter_fdn"] = db_merlinclash["merlinclash_subconverter_fdn"] = E("merlinclash_subconverter_fdn").checked ? '1' : '0';
	//merlinclash_subconverter_scv
	dbus_post["merlinclash_subconverter_scv"] = db_merlinclash["merlinclash_subconverter_scv"] = E("merlinclash_subconverter_scv").checked ? '1' : '0';
	dbus_post["merlinclash_subconverter_tfo"] = db_merlinclash["merlinclash_subconverter_tfo"] = E("merlinclash_subconverter_tfo").checked ? '1' : '0';
	push_data("clash_online_yaml4.sh", action,  dbus_post);
	
}
function get_online_yaml4(action) {
	var dbus_post = {};
	if(!$.trim($('#merlinclash_dc_subconverter_include').val())){
		var include = "";
	}else{
		var include = encodeURIComponent(E("merlinclash_dc_subconverter_include").value);
	}
	if(!$.trim($('#merlinclash_dc_subconverter_exclude').val())){
		var exclude = "";
	}else{
		var exclude = encodeURIComponent(E("merlinclash_dc_subconverter_exclude").value);
	}
	var dcss = document.getElementById("dc_ss_1").innerHTML;
	var dcv2 = document.getElementById("dc_v2_1").innerHTML;
	var dctj = document.getElementById("dc_trojan_1").innerHTML;
	if(dcss == "null"){
		dcss = ""
	}
	if(dcv2 == "null"){
		dcv2 = ""
	}
	if(dctj == "null"){
		dctj = ""
	}
	var links3 = dcss + "|" + dcv2 + "|" + dctj;
	//20210916+++
	if(E("merlinclash_dc_customurl_cbox").checked){
		if(!$.trim($('#merlinclash_dc_uploadiniurl').val())){
			alert("远程配置地址不能为空！");
			return false;
		}
		dcurlbase64 = Base64.encode(encodeURIComponent(E("merlinclash_dc_uploadiniurl").value));
		dbus_post["merlinclash_dc_uploadiniurl"] = db_merlinclash["merlinclash_dc_uploadiniurl"] = dcurlbase64;
	}
	dbus_post["merlinclash_dc_customurl_cbox"] = db_merlinclash["merlinclash_dc_customurl_cbox"] = E("merlinclash_dc_customurl_cbox").checked ? '1' : '0';
	
	//20210916---
	//links3 = encodeURIComponent(links3);
	links3 = Base64.encode(encodeURIComponent(links3));
	dbus_post["merlinclash_dc_links3"] = links3;
	dbus_post["merlinclash_dc_uploadrename4"] = "dler_3in1";
	dbus_post["merlinclash_action"] = db_merlinclash["merlinclash_action"] = action;
	//20200630+++
	dbus_post["merlinclash_dc_acl4ssrsel"] = db_merlinclash["merlinclash_dc_acl4ssrsel"] = E("merlinclash_dc_acl4ssrsel").value;
	//20200630---
	//20200804
	dbus_post["merlinclash_dc_clashtarget"] = db_merlinclash["merlinclash_dc_clashtarget"] = E("merlinclash_dc_clashtarget").value;
	dbus_post["merlinclash_dc_subconverter_include"] = db_merlinclash["merlinclash_dc_subconverter_include"] = include;
	dbus_post["merlinclash_dc_subconverter_exclude"] = db_merlinclash["merlinclash_dc_subconverter_exclude"] = exclude;
	dbus_post["merlinclash_dc_subconverter_emoji"] = db_merlinclash["merlinclash_dc_subconverter_emoji"] = E("merlinclash_dc_subconverter_emoji").checked ? '1' : '0';
	dbus_post["merlinclash_dc_subconverter_udp"] = db_merlinclash["merlinclash_dc_subconverter_udp"] = E("merlinclash_dc_subconverter_udp").checked ? '1' : '0';
	dbus_post["merlinclash_dc_subconverter_append_type"] = db_merlinclash["merlinclash_dc_subconverter_append_type"] = E("merlinclash_dc_subconverter_append_type").checked ? '1' : '0';
	dbus_post["merlinclash_dc_subconverter_sort"] = db_merlinclash["merlinclash_dc_subconverter_sort"] = E("merlinclash_dc_subconverter_sort").checked ? '1' : '0';
	dbus_post["merlinclash_dc_subconverter_fdn"] = db_merlinclash["merlinclash_dc_subconverter_fdn"] = E("merlinclash_dc_subconverter_fdn").checked ? '1' : '0';
	//merlinclash_subconverter_scv
	dbus_post["merlinclash_dc_subconverter_scv"] = db_merlinclash["merlinclash_dc_subconverter_scv"] = E("merlinclash_dc_subconverter_scv").checked ? '1' : '0';
	dbus_post["merlinclash_dc_subconverter_tfo"] = db_merlinclash["merlinclash_dc_subconverter_tfo"] = E("merlinclash_dc_subconverter_tfo").checked ? '1' : '0';
	push_data("clash_online_yaml4.sh", action,  dbus_post);
	
	
}
//------------------------------------导出全局数据 BEGIN--------------------------------------------
function down_clashdata(arg) {
	var id = parseInt(Math.random() * 100000000);
	var postData = {"id": id, "method": "clash_downdata.sh", "params":[arg], "fields": "" };
	$.ajax({
		type: "POST",
		url: "/_api/",
		async: true,
		cache:false,
		data: JSON.stringify(postData),
		dataType: "json",
		success: function(response){
			if(response.result == id){
				if(arg == 1){
					var downloadA = document.createElement('a');
					var josnData = {};
					var a = "http://"+window.location.hostname+"/_temp/"+"clash_backup.tar.gz"
					var blob = new Blob([JSON.stringify(josnData)],{type : 'application/json'});
					downloadA.href = a;
					downloadA.download = "clash_backup.tar.gz";
					downloadA.click();
					window.URL.revokeObjectURL(downloadA.href);
				}
			}
		}
	});	
}
function upload_clashdata() {
	if(!$.trim($('#clashdata').val())){
		alert("请先选择文件");
		return false;
	}
	require(['/res/layer/layer.js'], function(layer) {
		layer.confirm('<li>请确保补丁文件合法！仍要上传安装补丁吗？</li>', {
			shade: 0.8,
		}, function(index) {
			var filename = $("#clashdata").val();
			filename = filename.split('\\');
			filename = filename[filename.length - 1];
			var lastindex = filename.lastIndexOf('.')
			filelast = filename.substring(lastindex)
			if (filelast != ".gz" ) {
				console.log(filename);
				console.log(filelast);
				alert('上传文件格式不正确！');

				return false;
			}
			E('clashdata_info').style.display = "none";
			var formData = new FormData();
			formData.append("clash_backup.tar.gz", $('#clashdata')[0].files[0]);
			$.ajax({
				url: '/_upload',
				type: 'POST',
				cache: false,
				data: formData,
				processData: false,
				contentType: false,
				complete: function(res) {
					if (res.status == 200) {
						E('clashdata_info').style.display = "block";
						restore_clash_data();
					}
				}
			});	
			layer.close(index);
					return true;			
		}, function(index) {
			layer.close(index);
			return false;
		});
	});	
}
function restore_clash_data() {
	showMCLoadingBar();
	var dbus_post = {};
	var id = parseInt(Math.random() * 100000000);
	dbus_post["merlinclash_action"] = db_merlinclash["merlinclash_action"] = action = 27;
	push_data("clash_downdata.sh", action,  dbus_post);
}
//------------------------------------导出全局数据 END--------------------------------------------
//------------------------------------导出自定义规则以及还原 BEGIN--------------------------------------------
function down_clashrestorerule(arg) {
	var id = parseInt(Math.random() * 100000000);
	var postData = {"id": id, "method": "clash_downrule.sh", "params":[arg], "fields": "" };
	$.ajax({
		type: "POST",
		url: "/_api/",
		async: true,
		cache:false,
		data: JSON.stringify(postData),
		dataType: "json",
		success: function(response){
			if(response.result == id){
				if(arg == 1){
					var downloadA = document.createElement('a');
					var josnData = {};
					var a = "http://"+window.location.hostname+"/_temp/"+"clash_rulebackup.sh"
					var blob = new Blob([JSON.stringify(josnData)],{type : 'application/json'});
					downloadA.href = a;
					downloadA.download = "clash_rulebackup.sh";
					downloadA.click();
					window.URL.revokeObjectURL(downloadA.href);
				}
			}
		}
	});	
}
function upload_clashrestorerule() {
	var filename = $("#clashrestorerule").val();
	filename = filename.split('\\');
	filename = filename[filename.length - 1];
	var filelast = filename.split('.');
	filelast = filelast[filelast.length - 1];
	if (filelast != "sh" ) {
		alert('备份文件格式不正确！');
		return false;
	}
	E('clashrestorerule_info').style.display = "none";
	var formData = new FormData();
	formData.append("clash_rulebackup.sh", $('#clashrestorerule')[0].files[0]);
	$.ajax({
		url: '/_upload',
		type: 'POST',
		cache: false,
		data: formData,
		processData: false,
		contentType: false,
		complete: function(res) {
			if (res.status == 200) {
				E('clashrestorerule_info').style.display = "block";
				restore_clash_rule();
			}
		}
	});	
}
function restore_clash_rule() {
	showMCLoadingBar();
	var dbus_post = {};
	var id = parseInt(Math.random() * 100000000);
	dbus_post["merlinclash_action"] = db_merlinclash["merlinclash_action"] = action = 23;
	push_data("clash_downrule.sh", action,  dbus_post);
}
//------------------------------------导出自定义规则以及还原 END--------------------------------------------
//------------------------------------导出绕行设置以及还原 BEGIN--------------------------------------------
function down_passdevice(arg) {
	var id = parseInt(Math.random() * 100000000);
	var postData = {"id": id, "method": "clash_downpassdevice.sh", "params":[arg], "fields": "" };
	$.ajax({
		type: "POST",
		url: "/_api/",
		async: true,
		cache:false,
		data: JSON.stringify(postData),
		dataType: "json",
		success: function(response){
			if(response.result == id){
				if(arg == 1){
					var downloadA = document.createElement('a');
					var josnData = {};
					var a = "http://"+window.location.hostname+"/_temp/"+"clash_passdevicebackup.sh"
					var blob = new Blob([JSON.stringify(josnData)],{type : 'application/json'});
					downloadA.href = a;
					downloadA.download = "clash_passdevicebackup.sh";
					downloadA.click();
					window.URL.revokeObjectURL(downloadA.href);
				}
			}
		}
	});	
}
function upload_passdevice() {
	var filename = $("#passdevice").val();
	filename = filename.split('\\');
	filename = filename[filename.length - 1];
	var filelast = filename.split('.');
	filelast = filelast[filelast.length - 1];
	if (filelast != "sh" ) {
		alert('备份文件格式不正确！');
		return false;
	}
	E('passdevice_info').style.display = "none";
	var formData = new FormData();
	formData.append("clash_passdevicebackup.sh", $('#passdevice')[0].files[0]);
	$.ajax({
		url: '/_upload',
		type: 'POST',
		cache: false,
		data: formData,
		processData: false,
		contentType: false,
		complete: function(res) {
			if (res.status == 200) {
				E('passdevice_info').style.display = "block";
				restore_passdevice();
			}
		}
	});	
}
function restore_passdevice() {
	showMCLoadingBar();
	var dbus_post = {};
	var id = parseInt(Math.random() * 100000000);
	dbus_post["merlinclash_action"] = db_merlinclash["merlinclash_action"] = action = 24;
	push_data("clash_downpassdevice.sh", action,  dbus_post);
}
//------------------------------------导出绕行设置以及还原 END-------------------------------------------
function ssconvert(action) {
	var dbus_post = {};
	if(!$.trim($('#merlinclash_uploadrename3').val())){
		alert("重命名框不能为空！");
		return false;
	}
	dbus_post["merlinclash_uploadrename3"] = db_merlinclash["merlinclash_uploadrename3"] = (E("merlinclash_uploadrename3").value);
	dbus_post["merlinclash_action"] = db_merlinclash["merlinclash_action"] = action;
	push_data("clash_online_yaml3.sh", action,  dbus_post);
}
//------------------------------------------删除配置 BEGIN--------------------------------------
function del_yaml_sel(action) {
	var dbus_post = {};
	if(!$.trim($('#merlinclash_delyamlsel').val())){
		alert("配置文件不能为空！");
		return false;
	}
	if(E("merlinclash_delyamlsel").value == db_merlinclash["merlinclash_yamlsel"]){
		alert("选择的配置文件为当前使用文件，不予删除！");
		return false;
	}
	dbus_post["merlinclash_delyamlsel"] = db_merlinclash["merlinclash_delyamlsel"] = (E("merlinclash_delyamlsel").value);
	dbus_post["merlinclash_action"] = db_merlinclash["merlinclash_action"] = "4"
	push_data("clash_delyamlsel.sh", action, dbus_post);
}
//------------------------------------------删除配置 END--------------------------------------
//------------------------------------------删除ini配置 BEGIN--------------------------------------
function del_ini_sel(action) {
	var dbus_post = {};
	if(!$.trim($('#merlinclash_delinisel').val())){
		alert("ini配置文件不能为空！");
		return false;
	}
	dbus_post["merlinclash_delinisel"] = db_merlinclash["merlinclash_delinisel"] = (E("merlinclash_delinisel").value);
	dbus_post["merlinclash_action"] = db_merlinclash["merlinclash_action"] = action
	push_data("clash_delyamlsel.sh", action, dbus_post);
}
//------------------------------------------删除ini配置 END--------------------------------------
//------------------------------------------删除list BEGIN--------------------------------------
function del_list_sel(action) {
	var dbus_post = {};
	if(!$.trim($('#merlinclash_dellistsel').val())){
		alert("list文件不能为空！");
		return false;
	}
	dbus_post["merlinclash_dellistsel"] = db_merlinclash["merlinclash_dellistsel"] = (E("merlinclash_dellistsel").value);
	dbus_post["merlinclash_action"] = db_merlinclash["merlinclash_action"] = action
	push_data("clash_delyamlsel.sh", action, dbus_post);
}
//------------------------------------------删除list END--------------------------------------
function update_yaml_sel(action) {
	var dbus_post = {};
	if(!$.trim($('#merlinclash_delyamlsel').val())){
		alert("请选择一个配置文件！");
		return false;
	}
	dbus_post["merlinclash_delyamlsel"] = db_merlinclash["merlinclash_delyamlsel"] = (E("merlinclash_delyamlsel").value);
	dbus_post["merlinclash_action"] = db_merlinclash["merlinclash_action"] = "26"
	push_data("clash_updateyamlsel.sh", action, dbus_post);
}
//----------------------------下载配置 BEGIN-----------------------------
function download_yaml_sel(action) {
	//下载前清空/tmp/upload文件夹下的yaml格式文件	
	if(!$.trim($('#merlinclash_delyamlsel').val())){
		alert("配置文件不能为空！");
		return false;
	}
	var dbus_post = {};
	clear_yaml();
	dbus_post["merlinclash_delyamlsel"] = db_merlinclash["merlinclash_delyamlsel"] = (E("merlinclash_delyamlsel").value);
	var id = parseInt(Math.random() * 100000000);
	var postData = {"id": id, "method": "clash_downyamlsel.sh", "params":[action], "fields": dbus_post};
	var yamlname=""
	$.ajax({
		type: "POST",
		cache:false,
		url: "/_api/",
		data: JSON.stringify(postData),
		dataType: "json",
		success: function(response) {
			yamlname = response.result;
			download(yamlname);
		}
	});
}
function download(yamlname) {
	var downloadA = document.createElement('a');
	var josnData = {};
	var a = "http://"+window.location.hostname+"/_temp/"+yamlname
	var blob = new Blob([JSON.stringify(josnData)],{type : 'application/json'});
	downloadA.href = a;
	downloadA.download = yamlname;
	downloadA.click();
	window.URL.revokeObjectURL(downloadA.href);
}
//----------------------------下载配置 END-----------------------------
//----------------------------下载INI配置 BEGIN-----------------------------
function download_ini_sel(action) {
	//下载前清空/tmp/upload文件夹下的yaml格式文件	
	if(!$.trim($('#merlinclash_delinisel').val())){
		alert("配置文件不能为空！");
		return false;
	}
	var dbus_post = {};
	clear_yaml();
	dbus_post["merlinclash_delinisel"] = db_merlinclash["merlinclash_delinisel"] = (E("merlinclash_delinisel").value);
	var id = parseInt(Math.random() * 100000000);
	var postData = {"id": id, "method": "clash_downyamlsel.sh", "params":[action], "fields": dbus_post};
	var yamlname=""
	$.ajax({
		type: "POST",
		cache:false,
		url: "/_api/",
		data: JSON.stringify(postData),
		dataType: "json",
		success: function(response) {
			yamlname = response.result;
			download(yamlname);
		}
	});
}
//----------------------------下载INI配置 END-----------------------------
//----------------------------下载list BEGIN-----------------------------
function download_list_sel(action) {
	//下载前清空/tmp/upload文件夹下的yaml格式文件	
	if(!$.trim($('#merlinclash_dellistsel').val())){
		alert("配置文件不能为空！");
		return false;
	}
	var dbus_post = {};
	clear_yaml();
	dbus_post["merlinclash_dellistsel"] = db_merlinclash["merlinclash_dellistsel"] = (E("merlinclash_dellistsel").value);
	var id = parseInt(Math.random() * 100000000);
	var postData = {"id": id, "method": "clash_downyamlsel.sh", "params":[action], "fields": dbus_post};
	var yamlname=""
	$.ajax({
		type: "POST",
		cache:false,
		url: "/_api/",
		data: JSON.stringify(postData),
		dataType: "json",
		success: function(response) {
			yamlname = response.result;
			download(yamlname);
		}
	});
}
//----------------------------下载list END-----------------------------
//20200904下载HOST
function download_host() {
	var dbus_post = {};	
	var id = parseInt(Math.random() * 100000000);
	var postData = {"id": id, "method": "clash_downhost.sh", "params":[], "fields": dbus_post};
	$.ajax({
		type: "POST",
		cache:false,
		url: "/_api/",
		data: JSON.stringify(postData),
		dataType: "json",
		success: function(response) {
			hostfile = response.result;
			downloadhostfile(hostfile);
		}
	});
}
//20210415 删除HOST
//------------------------------------------删除HOST BEGIN--------------------------------------
function del_host_sel() {
	var dbus_post = {};
	if(!$.trim($('#merlinclash_hostsel').val())){
		alert("HOST文件不能为空！");
		return false;
	}
	if(E("merlinclash_hostsel").value == "default"){
		alert("默认host文件不予删除！");
		return false;
	}
	if(E("merlinclash_hostsel").value == db_merlinclash["merlinclash_hostsel_tmp"]){
		alert("当前使用的host文件不予删除！");
		return false;
	}
	dbus_post["merlinclash_hostsel"] = db_merlinclash["merlinclash_hostsel"] = (E("merlinclash_hostsel").value);
	action = dbus_post["merlinclash_action"] = db_merlinclash["merlinclash_action"] = "32"
	push_data("clash_delhostsel.sh", action, dbus_post);
}
//------------------------------------------删除HOST END--------------------------------------

function downloadhostfile() {
	var downloadA = document.createElement('a');
	var josnData = {};
	var a = "http://"+window.location.hostname+"/_temp/"+hostfile
	var blob = new Blob([JSON.stringify(josnData)],{type : 'application/json'});
	downloadA.href = a;
	downloadA.download = hostfile;
	downloadA.click();
	window.URL.revokeObjectURL(downloadA.href);
}
//20200904
function yaml_view() {
$.ajax({
		url: '/_temp/view.txt',
		type: 'GET',
		dataType: 'html',
		async: true,
		cache:false,
		success: function(response) {
			var retArea = E("yaml_content1");
			if (response.search("BBABBBBC") != -1) {
				retArea.value = response.replace("BBABBBBC", " ");
				var pageH = parseInt(E("FormTitle").style.height.split("px")[0]); 
				if(pageH){
					autoTextarea(E("yaml_content1"), 0, (pageH - 308));
				}else{
					autoTextarea(E("yaml_content1"), 0, 980);
				}
				return true;
			}
			retArea.value = response;
			_responseLen = response.length;
		},
		error: function(xhr) {
			E("yaml_content1").value = "获取配置文件信息失败！";
		}
	});
}
//在线获取广告区
function notice_show() {
	$.ajax({
		url: 'https://raw.githubusercontent.com/flyhigherpi/merlinclash_clash_related/master/push_message.json.js',
		type: 'GET',
		dataType: 'json',
		success: function(res) {
			if(res.content1){
				$("#showmsg1").html("<i>"+res.content1+"</i>");
			}
			if(res.content2){
				$("#showmsg2").html("<i>"+res.content2+"</i>");
			}
			if(res.content3){
				$("#showmsg3").html("<i>"+res.content3+"</i>");
			}
			if(res.content4){
				$("#showmsg4").html("<i>"+res.content4+"</i>");
			}
			
		}
	});
}
//检查版本更新
function update_mc() {
	var dbus_post = {};
	db_merlinclash["merlinclash_action"] = "20";
	push_data("clash_update_version.sh", "update",  dbus_post);
}

function node_remark_view() {
	var txt = E("merlinclash_yamlsel").value;
$.ajax({		
		url: '/_temp/merlinclash_node_mark.log',
		type: 'GET',
		dataType: 'html',
		async: true,
		cache:false,
		success: function(response) {
			var retArea = E("nodes_content1");
			if (response.search("BBABBBBC") != -1) {
				retArea.value = response.replace("BBABBBBC", " ");
				var pageH = parseInt(E("FormTitle").style.height.split("px")[0]); 
				if(pageH){
					autoTextarea(E("nodes_content1"), 0, (pageH - 308));
				}else{
					autoTextarea(E("nodes_content1"), 0, 980);
				}
				return true;
			}
			retArea.value = response;
			_responseLen = response.length;
		},
		error: function(xhr) {
			E("nodes_content1").value = "获取节点还原信息失败！";
		}
	});
}
function get_log() {
	$.ajax({
		url: '/_temp/merlinclash_log.txt',
		type: 'GET',
		dataType: 'html',
		async: true,
		cache:false,
		success: function(response) {
			var retArea = E("log_content1");
			if (response.search("BBABBBBC") != -1) {
				retArea.value = response.replace("BBABBBBC", " ");
				var pageH = parseInt(E("FormTitle").style.height.split("px")[0]); 
				if(pageH){
					autoTextarea(E("log_content1"), 0, (pageH - 308));
				}else{
					autoTextarea(E("log_content1"), 0, 980);
				}
				return true;
			}
			if (_responseLen == response.length) {
				noChange++;
			} else {
				noChange = 0;
			}
			if (noChange > 5) {
				return false;
			} else {
				setTimeout("get_log();", 300);
			}
			retArea.value = response;
			_responseLen = response.length;
		},
		error: function(xhr) {
			E("log_content1").value = "获取日志失败！";
		}
	});
}
function count_down_close1() {
	if (x == "0") {
		hideMCLoadingBar();
	}
	if (x < 0) {
		E("ok_button1").value = "手动关闭"
		return false;
	}
	E("ok_button1").value = "自动关闭（" + x + "）"
		--x;
	setTimeout("count_down_close1();", 1000);
}
function get_realtime_log() {
	$.ajax({
		url: '/_temp/merlinclash_log.txt',
		type: 'GET',
		async: true,
		cache: false,
		dataType: 'text',
		success: function(response) {
			var retArea = E("log_content3");
			if (response.search("BBABBBBC") != -1) {
				retArea.value = response.replace("BBABBBBC", " ");
				E("ok_button").style.display = "";
				retArea.scrollTop = retArea.scrollHeight;
				count_down_close1();
				return true;
			}
			if (_responseLen == response.length) {
				noChange++;
			} else {
				noChange = 0;
			}
			if (noChange > 1000) {
				return false;
			} else {
				setTimeout("get_realtime_log();", 500);
			}
			retArea.value = response.replace("BBABBBBC", " ");
			retArea.scrollTop = retArea.scrollHeight;
			_responseLen = response.length;
		},
		error: function() {
			setTimeout("get_realtime_log();", 500);
		}
	});
}
function get_realtime_log_sim() {
	$.ajax({
		url: '/_temp/merlinclash_simlog.txt',
		type: 'GET',
		async: true,
		cache: false,
		dataType: 'text',
		success: function(response) {
			var retArea = E("log_content3");
			if (response.search("BBABBBBC") != -1) {
				retArea.value = response.replace("BBABBBBC", " ");
				E("ok_button").style.display = "";
				retArea.scrollTop = retArea.scrollHeight;
				count_down_close1();
				return true;
			}
			if (_responseLen == response.length) {
				noChange++;
			} else {
				noChange = 0;
			}
			if (noChange > 1000) {
				return false;
			} else {
				setTimeout("get_realtime_log_sim();", 3000);
			}
			retArea.value = response.replace("BBABBBBC", " ");
			retArea.scrollTop = retArea.scrollHeight;
			_responseLen = response.length;
		},
		error: function() {
			setTimeout("get_realtime_log_sim();", 1000);
		}
	});
}
//
function getradioval(sel_tmp) {
	if (sel_tmp == "1"){
		var radio = document.getElementsByName("dnsplan");
		for(i = 0; i< radio.length; i++){
			if(radio[i].checked){
				return radio[i].value
			}
		}
	}
	if (sel_tmp == "2"){
		var yamlsel = document.getElementsByName("yamlsel");
		for(i = 0; i< yamlsel.length; i++){
			if(yamlsel[i].checked){
				return yamlsel[i].value
			}
		}
	}
	if (sel_tmp == "3"){
		var clashmodesel = document.getElementsByName("clashmode");
		for(i = 0; i< clashmodesel.length; i++){
			if(clashmodesel[i].checked){
				return clashmodesel[i].value
			}
		}
	}
	if (sel_tmp == "4"){
		var tproxymodesel = document.getElementsByName("tproxymode");
		for(i = 0; i< tproxymodesel.length; i++){
			if(tproxymodesel[i].checked){
				return tproxymodesel[i].value
			}
		}
	}
	if (sel_tmp == "5"){
		var iptablessel = document.getElementsByName("iptablessel");
		for(i = 0; i< iptablessel.length; i++){
			if(iptablessel[i].checked){
				return iptablessel[i].value
			}
		}
	}
	if (sel_tmp == "6"){
		var unblockplan = document.getElementsByName("unblockplan");
		for(i = 0; i< unblockplan.length; i++){
			if(unblockplan[i].checked){
				return unblockplan[i].value
			}
		}
	}
	if (sel_tmp == "7"){
		var dnshijacksel = document.getElementsByName("dnshijack");
		for(i = 0; i< dnshijacksel.length; i++){
			if(dnshijacksel[i].checked){
				return dnshijacksel[i].value
			}
		}
	}
}
function reload_Soft_Center() {
	location.href = "/Module_Softcenter.asp";
}
function load_cron_params() {

	for (var i = 0; i < 24; i++){
		var _tmp = [];
		var _tmp0 = [];
		_i = String(i)
		_tmp0 = _i;
		_tmp = _i + "时";
		$("#merlinclash_select_hour").append("<option value='"+_tmp0+"' >"+_tmp+"</option>");
		$("#merlinclash_select_regular_hour").append("<option value='"+_tmp0+"' >"+_tmp+"</option>");
		$("#merlinclash_select_clash_restart_hour").append("<option value='"+_tmp0+"' >"+_tmp+"</option>");
	}

	for (var i = 0; i < 61; i++){
		var _tmp = [];
		var _tmp0 = [];
		_i = String(i)
		_tmp0 = _i;
		_tmp = _i + "分";
		$("#merlinclash_select_minute").append("<option value='"+_tmp0+"' >"+_tmp+"</option>");
		$("#merlinclash_select_regular_minute").append("<option value='"+_tmp0+"' >"+_tmp+"</option>");
		$("#merlinclash_select_clash_restart_minute").append("<option value='"+_tmp0+"' >"+_tmp+"</option>");
	}
	var option_rebw = [["1", "一"], ["2", "二"], ["3", "三"], ["4", "四"], ["5", "五"], ["6", "六"], ["7", "日"]];
	for (var i = 0; i < option_rebw.length; i++){
		var _tmp = [];
		var _tmp0 = [];
		_i = String(i)
		_tmp = option_rebw[_i];
		_tmp1 = _tmp[1];
		_tmp0 = _tmp[0];
		$("#merlinclash_select_week").append("<option value='"+_tmp0+"' >"+_tmp1+"</option>");
		$("#merlinclash_select_regular_week").append("<option value='"+_tmp0+"' >"+_tmp1+"</option>");
		$("#merlinclash_select_clash_restart_week").append("<option value='"+_tmp0+"' >"+_tmp1+"</option>");
	}
	var option_trit = [["2", "2分钟"], ["5", "5分钟"], ["10", "10分钟"], ["15", "15分钟"], ["20", "20分钟"], ["25", "25分钟"], ["30", "30分钟"], ["1", "1小时"], ["3", "3小时"], ["6", "6小时"], ["12", "12小时"]];
	for (var i = 0; i < option_trit.length; i++){
		var _tmp = [];
		var _tmp0 = [];
		_i = String(i)
		_tmp = option_trit[_i];
		_tmp1 = _tmp[1];
		_tmp0 = _tmp[0];
		$("#merlinclash_select_regular_minute_2").append("<option value='"+_tmp0+"' >"+_tmp1+"</option>");
		$("#merlinclash_select_clash_restart_minute_2").append("<option value='"+_tmp0+"' >"+_tmp1+"</option>");
	}
	for (var i = 1; i < 32; i++){
		var _tmp = [];
		var _tmp0 = [];
		_i = String(i)
		_tmp0 = _i;
		_tmp = _i + "日";
		$("#merlinclash_select_day").append("<option value='"+_tmp0+"' >"+_tmp+"</option>");
		$("#merlinclash_select_regular_day").append("<option value='"+_tmp0+"' >"+_tmp+"</option>");
		$("#merlinclash_select_clash_restart_day").append("<option value='"+_tmp0+"' >"+_tmp+"</option>");
	}
}
function show_job() {
	var option_rebw = [["1", "一"], ["2", "二"], ["3", "三"], ["4", "四"], ["5", "五"], ["6", "六"], ["7", "日"]];
	if (E("merlinclash_select_job").value == "1" ){
		$('#merlinclash_select_hour').hide();
		$('#merlinclash_select_minute').hide();
		$('#merlinclash_select_day').hide(); 
		$('#merlinclash_select_week').hide(); 
	}
	else if (E("merlinclash_select_job").value == "2" ){
		$('#merlinclash_select_hour').show();
		$('#merlinclash_select_minute').show();
		$('#merlinclash_select_week').hide(); 
		$('#merlinclash_select_day').hide(); 
	}
	else if (E("merlinclash_select_job").value == "3" ){
		$('#merlinclash_select_hour').show();
		$('#merlinclash_select_minute').show();
		$('#merlinclash_select_day').hide(); 
		$('#merlinclash_select_week').show(); 
	}
	else if (E("merlinclash_select_job").value == "4" ){
		$('#merlinclash_select_day').show(); 
		$('#merlinclash_select_hour').show();
		$('#merlinclash_select_minute').show();
		$('#merlinclash_select_week').hide(); 
	}
	if (E("merlinclash_select_regular_subscribe").value == "1" ){
		$('#merlinclash_select_regular_hour').hide();
		$('#merlinclash_select_regular_minute').hide();
		$('#merlinclash_select_regular_day').hide(); 
		$('#merlinclash_select_regular_week').hide(); 
		$('#merlinclash_select_regular_minute_2').hide(); 
	}
	else if (E("merlinclash_select_regular_subscribe").value == "2" ){
		$('#merlinclash_select_regular_hour').show();
		$('#merlinclash_select_regular_minute').show();
		$('#merlinclash_select_regular_week').hide(); 
		$('#merlinclash_select_regular_day').hide(); 
		$('#merlinclash_select_regular_minute_2').hide(); 
	}
	else if (E("merlinclash_select_regular_subscribe").value == "3" ){
		$('#merlinclash_select_regular_hour').show();
		$('#merlinclash_select_regular_minute').show();
		$('#merlinclash_select_regular_day').hide(); 
		$('#merlinclash_select_regular_week').show(); 
		$('#merlinclash_select_regular_minute_2').hide(); 
	}
	else if (E("merlinclash_select_regular_subscribe").value == "4" ){
		$('#merlinclash_select_regular_day').show(); 
		$('#merlinclash_select_regular_hour').show();
		$('#merlinclash_select_regular_minute').show();
		$('#merlinclash_select_regular_week').hide(); 
		$('#merlinclash_select_regular_minute_2').hide(); 
	} 
	else if (E("merlinclash_select_regular_subscribe").value == "5" ){
		$('#merlinclash_select_regular_day').hide(); 
		$('#merlinclash_select_regular_hour').hide();
		$('#merlinclash_select_regular_minute').hide();
		$('#merlinclash_select_regular_week').hide(); 
		$('#merlinclash_select_regular_minute_2').show(); 
	} 
	if (E("merlinclash_select_clash_restart").value == "1" ){
		$('#merlinclash_select_clash_restart_hour').hide();
		$('#merlinclash_select_clash_restart_minute').hide();
		$('#merlinclash_select_clash_restart_day').hide(); 
		$('#merlinclash_select_clash_restart_week').hide(); 
		$('#merlinclash_select_clash_restart_minute_2').hide(); 
	}
	else if (E("merlinclash_select_clash_restart").value == "2" ){
		$('#merlinclash_select_clash_restart_hour').show();
		$('#merlinclash_select_clash_restart_minute').show();
		$('#merlinclash_select_clash_restart_week').hide(); 
		$('#merlinclash_select_clash_restart_day').hide(); 
		$('#merlinclash_select_clash_restart_minute_2').hide(); 
	}
	else if (E("merlinclash_select_clash_restart").value == "3" ){
		$('#merlinclash_select_clash_restart_hour').show();
		$('#merlinclash_select_clash_restart_minute').show();
		$('#merlinclash_select_clash_restart_day').hide(); 
		$('#merlinclash_select_clash_restart_week').show(); 
		$('#merlinclash_select_clash_restart_minute_2').hide(); 
	}
	else if (E("merlinclash_select_clash_restart").value == "4" ){
		$('#merlinclash_select_clash_restart_day').show(); 
		$('#merlinclash_select_clash_restart_hour').show();
		$('#merlinclash_select_clash_restart_minute').show();
		$('#merlinclash_select_clash_restart_week').hide(); 
		$('#merlinclash_select_clash_restart_minute_2').hide(); 
	} 
	else if (E("merlinclash_select_clash_restart").value == "5" ){
		$('#merlinclash_select_clash_restart_day').hide(); 
		$('#merlinclash_select_clash_restart_hour').hide();
		$('#merlinclash_select_clash_restart_minute').hide();
		$('#merlinclash_select_clash_restart_week').hide(); 
		$('#merlinclash_select_clash_restart_minute_2').show(); 
	} 
}
function dc_login() {
    var dbus_post = {};
    dbus_post["merlinclash_dc_name"] = db_merlinclash["merlinclash_dc_name"] = E("merlinclash_dc_name").value;
    dbus_post["merlinclash_dc_passwd"] = db_merlinclash["merlinclash_dc_passwd"] = E("merlinclash_dc_passwd").value;
	var arg="login"
    var id = parseInt(Math.random() * 100000000);
	var postData = {"id": id, "method": "clash_dclogin.sh", "params":[arg], "fields": dbus_post};
	$.ajax({
		type: "POST",
		url: "/_api/",
		async: true,
		data: JSON.stringify(postData),
		success: function(response) {
			var arr = response.result;	
            if (arr != "200"){
                alert("登陆用户名/密码有误。");
                return false;
            } else{
                dc_info();
            }			
		}
	});
}

function dc_logout() {
    var dbus_post = {};
    dbus_post["merlinclash_dc_name"] = db_merlinclash["merlinclash_dc_name"] = E("merlinclash_dc_name").value;
    dbus_post["merlinclash_dc_passwd"] = db_merlinclash["merlinclash_dc_passwd"] = E("merlinclash_dc_passwd").value;
	var arg="logout"
    var id = parseInt(Math.random() * 100000000);
	var postData = {"id": id, "method": "clash_dclogin.sh", "params":[arg], "fields": dbus_post};
	$.ajax({
		type: "POST",
		url: "/_api/",
		async: true,
		data: JSON.stringify(postData),
		success: function(response) {
            tabSelect(10);
            $('#dlercloud_login').show(); 
            $('#dlercloud_content').hide(); 
		}
	});
    
}
//初始化页面时决定栏目显示哪个div层
function dc_init() {
    //初次未登录，显示登陆栏，此时token为空。
    if(db_merlinclash["merlinclash_dc_token"] == "" || db_merlinclash["merlinclash_dc_token"] == null){
        $('#dlercloud_login').show();
        $('#dlercloud_content').hide();  
        return false;        
    }   
    //token失效，退回登陆栏；有效则重新获取最新的套餐信息
    if(db_merlinclash["merlinclash_dc_token"]){
        var dbus_post = {};
        var arg="token"
        var id = parseInt(Math.random() * 100000000);
        var postData = {"id": id, "method": "clash_dclogin.sh", "params":[arg], "fields": dbus_post};
        $.ajax({
            type: "POST",
            url: "/_api/",
            async: true,
            data: JSON.stringify(postData),
            success: function(response) {
                var arr = response.result.split("@@");	
                if (arr[0] != "200"){
                    alert("DlerCloud用户/密码错，请重新登陆");
                    $('#dlercloud_login').show(); 
                    $('#dlercloud_content').hide(); 
                    return false;
                } else{
                    E("dc_name").innerHTML = arr[1];
					E("dc_token").innerHTML = arr[10];
					E("dc_money").innerHTML = arr[4];
					E("dc_affmoney").innerHTML = arr[11];
					E("dc_integral").innerHTML = arr[12];
					E("dc_plan").innerHTML = arr[2];	
					E("dc_plantime").innerHTML = arr[3];
                    E("dc_usedTraffic").innerHTML = arr[5];
                    E("dc_unusedTraffic").innerHTML = arr[6];
                    E("dc_ss").innerHTML = arr[7];
                    E("dc_v2").innerHTML = arr[8];
                    E("dc_trojan").innerHTML = arr[9];  
                    $('#dlercloud_login').hide(); 
                    $('#dlercloud_content').show();
					dc_info_show(); 
                    return false;                 
                }	    
            }
        });
    }
}
function open_user_rule(){
	$("#vpnc_settings").fadeIn(200);
}
function close_user_rule(){
	$("#vpnc_settings").fadeOut(200);
}
function dc_info() {
    tabSelect(10);
    dc_info_show();
    $('#dlercloud_login').hide(); 
    $('#dlercloud_content').show(); 
    
}

function dc_info_show() {
    var dbus_post = {};
    var arg="info"
    var id = parseInt(Math.random() * 100000000);
	var postData = {"id": id, "method": "clash_dclogin.sh", "params":[arg], "fields": dbus_post};
	$.ajax({
		type: "POST",
		url: "/_api/",
		async: true,
		data: JSON.stringify(postData),
		success: function(response) {
			var arr = response.result.split("@@");	
            if (arr[0] != "200"){
                alert(arr[0]);
                return false;
            } else{
                E("dc_name").innerHTML = arr[1];
				E("dc_token").innerHTML = arr[10];
                E("dc_money").innerHTML = arr[4];
				E("dc_affmoney").innerHTML = arr[11];
				E("dc_integral").innerHTML = arr[12];
                E("dc_plan").innerHTML = arr[2];
                E("dc_plantime").innerHTML = arr[3];
                E("dc_usedTraffic").innerHTML = arr[5];
                E("dc_unusedTraffic").innerHTML = arr[6];
                E("dc_ss").innerHTML = arr[7];
                E("dc_v2").innerHTML = arr[8];
                E("dc_trojan").innerHTML = arr[9];
                
            }			
		}
	});
}


function clear_yaml() {
	var id = parseInt(Math.random() * 100000000);
	var postData = {"id": id, "method": "clash_clearyaml.sh", "params":[], "fields": ""};
	var yamlname=""
	$.ajax({
		type: "POST",
		cache:false,
		url: "/_api/",
		data: JSON.stringify(postData),
		dataType: "json",
		success: function(response) {
		}
	});
}
function get_dnsyaml(dns_tag) {
	var id = parseInt(Math.random() * 100000000);
	var dbus_post={};
	dbus_post["merlinclash_dnsedit_tag"] = db_merlinclash["merlinclash_dnsedit_tag"] = dns_tag;
	var postData = {"id": id, "method": "clash_getdnsyaml.sh", "params":[], "fields": dbus_post};
	$.ajax({
		type: "POST",
		cache:false,
		url: "/_api/",
		data: JSON.stringify(postData),
		dataType: "json",
		success: function(response) {
			dns_yaml_view(dns_tag);
		}
	});
}
function get_host(host_tag) {
	var id = parseInt(Math.random() * 100000000);
	var dbus_post={};
	dbus_post["merlinclash_hostsel"] = db_merlinclash["merlinclash_hostsel"] = host_tag;
	var postData = {"id": id, "method": "clash_gethost.sh", "params":[], "fields": dbus_post};
	$.ajax({
		type: "POST",
		cache:false,
		url: "/_api/",
		data: JSON.stringify(postData),
		dataType: "json",
		success: function(response) {
			host_view(host_tag);
		}
	});
}
//修改clash运行模式
function PATCH_MODE(mode_tag) {
	var id = parseInt(Math.random() * 100000000);
	var dbus_post={};
	dbus_post["merlinclash_clashmode"] = db_merlinclash["merlinclash_clashmode"] = mode_tag;
	var postData = {"id": id, "method": "clash_patchmode.sh", "params":[], "fields": dbus_post};
	$.ajax({
		type: "POST",
		cache:false,
		url: "/_api/",
		data: JSON.stringify(postData),
		dataType: "json",
		success: function(response) {

		}
	});
}
//自定订阅规则切换显示
function set_rulemode() {
	if(db_merlinclash["merlinclash_flag"] == "HND"){
		var id = parseInt(Math.random() * 100000000);
		var dbus_post={};
		if(E("merlinclash_customrule_cbox").checked){	
			dbus_post["merlinclash_customrule_cbox"] = db_merlinclash["merlinclash_customrule_cbox"] = 1;
		}else{
			dbus_post["merlinclash_customrule_cbox"] = db_merlinclash["merlinclash_customrule_cbox"] = 0;	
		}
		var postData = {"id": id, "method": "dummy_script.sh", "params":[], "fields": dbus_post};
		$.ajax({
			type: "POST",
			cache:false,
			url: "/_api/",
			data: JSON.stringify(postData),
			dataType: "json",
			success: function(response) {
				if(E("merlinclash_customrule_cbox").checked){				
					document.getElementById("merlinclash_acl4ssrsel").style.display="none";  
					document.getElementById("merlinclash_acl4ssrsel_cus").style.display="";  
				}else{
					document.getElementById("merlinclash_acl4ssrsel").style.display="";  
					document.getElementById("merlinclash_acl4ssrsel_cus").style.display="none";  
				}
				document.getElementById("merlinclash_cdn_cbox").style.display="none";
				document.getElementById("merlinclash_cdn_cbox_span").style.display="none";
			}
		});
	}else{
		document.getElementById("merlinclash_acl4ssrsel_cus").style.display="none";
		document.getElementById("merlinclash_customrule_cbox").style.display="none";
		document.getElementById("merlinclash_customrule_cbox_span").style.display="none";
		document.getElementById("merlinclash_cdn_cbox").style.display="";
	}
}
//获取dns-yaml
function dns_yaml_view(dns_tag) {
$.ajax({
		url: '/_temp/dns_' + dns_tag + '.txt',
		type: 'GET',
		dataType: 'html',
		async: true,
		cache:false,
		success: function(response) {
			var retArea = E("merlinclash_dns_edit_content1");
			retArea.value = response;
			
		},
		error: function(xhr) {
			E("merlinclash_dns_edit_content1").value = "获取dns配置文件失败！";
		}
	});
}
//获取host-yaml
function host_view(host_tag) {
$.ajax({
		url: '/_temp/' + host_tag + '.txt',
		type: 'GET',
		dataType: 'html',
		async: true,
		cache:false,
		success: function(response) {
			var retArea = E("merlinclash_host_content1");
			retArea.value = response;
			
		},
		error: function(xhr) {
			E("merlinclash_host_content1").value = "获取host配置文件失败！";
		}
	});
}
//----------------下拉框获取script内容BEGIN--------------------------
function script_get(){	
	var id = parseInt(Math.random() * 100000000);
	var postData = {"id": id, "method": "clash_getscript.sh", "params":[], "fields": ""};
	$.ajax({
		type: "POST",
		cache:false,
		url: "/_api/",
		data: JSON.stringify(postData),
		dataType: "json",
		success: function(response) {
			if(response.result == id){
				script_yaml_view();
			}
		}
	});
}
//获取script-yaml
function script_yaml_view() {
$.ajax({
		url: '/_temp/clash_script.txt',
		type: 'GET',
		dataType: 'html',
		async: true,
		cache:false,
		success: function(response) {
			var retArea = E("merlinclash_script_edit_content1");
			retArea.value = response;		
		},
		error: function(xhr) {
			E("merlinclash_script_edit_content1").value = "获取script配置文件失败！";
		}
	});
}
function upload_unblockmusicbinary() {

if(!$.trim($('#unblockmusicbinary').val())){
	alert("请先选择二进制文件");
	return false;
}

require(['/res/layer/layer.js'], function(layer) {
	layer.confirm('<li>请确保二进制文件合法！仍要上传吗？</li>', {
		shade: 0.8,
	}, function(index) {
		E('unblockmusicbinary_upload').style.display = "none";
		var formData = new FormData();
		formData.append("UnblockNeteaseMusic", document.getElementById('unblockmusicbinary').files[0]);
		$.ajax({
			url: '/_upload',
			type: 'POST',
			cache: false,
			data: formData,
			processData: false,
			contentType: false,
			complete: function(res) {
				if (res.status == 200) {
					upload_unblockmusic();
				}
			}
		});
		layer.close(index);
		return true;			
	}, function(index) {
		layer.close(index);
		return false;
		});
	});
}
function upload_unblockmusic() {
	var dbus_post = {};
	action = dbus_post["merlinclash_action"] = db_merlinclash["merlinclash_action"] = "13"
	push_data("clash_local_unblockmusic_upload.sh", action,  dbus_post);
	E('unblockmusicbinary_upload').style.display = "block";
}
//------------------------------------------本地上传clash二进制 开始------------------------------------//
function upload_clashbinary() {

	if(!$.trim($('#clashbinary').val())){
		alert("请先选择clash文件");
		return false;
	}

	require(['/res/layer/layer.js'], function(layer) {
		layer.confirm('<li>请确保clash二进制文件合法！仍要替换clash吗？</li>', {
			shade: 0.8,
		}, function(index) {
			E('clashbinary_upload').style.display = "none";
			var formData = new FormData();
			formData.append("clash", document.getElementById('clashbinary').files[0]);
			$.ajax({
				url: '/_upload',
				type: 'POST',
				cache: false,
				data: formData,
				processData: false,
				contentType: false,
				complete: function(res) {
					if (res.status == 200) {
						upload_binary();
					}
				}
			});
			layer.close(index);
			return true;			
		}, function(index) {
			layer.close(index);
			return false;
		});
	});
	
	
}
function upload_binary() {
	var dbus_post = {};
	action = dbus_post["merlinclash_action"] = db_merlinclash["merlinclash_action"] = "12"
	push_data("clash_local_binary_upload.sh", action,  dbus_post);
	E('clashbinary_upload').style.display = "block";
}
//------------------------------------------本地上传clash二进制 结束------------------------------------//
//------------------------------------------本地上传补丁 开始------------------------------------//
function upload_clashpatch() {

	if(!$.trim($('#clashpatch').val())){
		alert("请先选择补丁包");
		return false;
	}

	require(['/res/layer/layer.js'], function(layer) {
		layer.confirm('<li>请确保补丁文件合法！仍要上传安装补丁吗？</li>', {
			shade: 0.8,
		}, function(index) {
			var patchname = $("#clashpatch").val();
			patchname = patchname.split('\\');
			patchname = patchname[patchname.length - 1];
			var lastindex = patchname.lastIndexOf('.')
			patchlast = patchname.substring(lastindex)
			if (patchlast != ".gz") {
				alert('补丁包格式不正确！');
				return false;
			}
			E('clashpatch_upload').style.display = "none";
			var formData = new FormData();
			formData.append(patchname, document.getElementById('clashpatch').files[0]);
			$.ajax({
				url: '/_upload',
				type: 'POST',
				cache: false,
				data: formData,
				processData: false,
				contentType: false,
				complete: function(res) {
					if (res.status == 200) {
						upload_patch(patchname);
					}
				}
			});
			layer.close(index);
			return true;			
		}, function(index) {
			layer.close(index);
			return false;
		});
	});	


}
function upload_patch(patchname) {
	var dbus_post = {};
	action = dbus_post["merlinclash_action"] = db_merlinclash["merlinclash_action"] = "15"
	dbus_post["merlinclash_uploadpatchname"] = db_merlinclash["merlinclash_uploadpatchname"] = patchname;
	push_data("clash_local_patch_upload.sh", action,  dbus_post);
	E('clashpatch_upload').style.display = "block";
}
//------------------------------------------本地上传补丁 结束------------------------------------//
//------------------------------------------本地上传kp规则 开始------------------------------------//
function upload_kprule() {

if(!$.trim($('#koolproxyrule').val())){
	alert("请先选择规则包");
	return false;
}

require(['/res/layer/layer.js'], function(layer) {
	layer.confirm('<li>请确保规则包文件合法！仍要上传规则包吗？</li>', {
		shade: 0.8,
	}, function(index) {
		var rulename = $("#koolproxyrule").val();
		rulename = rulename.split('\\');
		rulename = rulename[rulename.length - 1];
		var lastindex = rulename.lastIndexOf('.')
		rulelast = rulename.substring(lastindex)
		if (rulelast != ".gz") {
			alert('规则包格式不正确！');
			return false;
		}
		E('koolproxyrule_upload').style.display = "none";
		var formData = new FormData();
		formData.append(rulename, document.getElementById('koolproxyrule').files[0]);
		$.ajax({
			url: '/_upload',
			type: 'POST',
			cache: false,
			data: formData,
			processData: false,
			contentType: false,
			complete: function(res) {
				if (res.status == 200) {
					upload_rule(rulename);
				}
			}
		});
		layer.close(index);
		return true;			
	}, function(index) {
		layer.close(index);
		return false;
	});
});	


}
function upload_rule(rulename) {
var dbus_post = {};
action = dbus_post["merlinclash_action"] = db_merlinclash["merlinclash_action"] = "33"
dbus_post["merlinclash_uploadrulename"] = db_merlinclash["merlinclash_uploadrulename"] = rulename;
push_data("clash_local_kprule_upload.sh", action,  dbus_post);
E('koolproxyrule_upload').style.display = "block";
}
//------------------------------------------本地上传KP规则 结束------------------------------------//
//上传ini配置文件到/tmp/upload文件夹
//------------------------------------------本地上传ini配置 开始------------------------------------//
function upload_clashinifile() {
	var filename = $("#clashinifile").val();
	filename = filename.split('\\');
	filename = filename[filename.length - 1];
	var filelast = filename.split('.');
	filelast = filelast[filelast.length - 1];
	if (filelast != "ini") {
		alert('上传文件格式非法！只支持上传ini后缀的配置文件');
		return false;
	}
	E('clashinifile_info').style.display = "none";
	var formData = new FormData();
	
	formData.append(filename, document.getElementById('clashinifile').files[0]);

	$.ajax({
		url: '/_upload',
		type: 'POST',
		cache: false,
		data: formData,
		processData: false,
		contentType: false,
		complete: function(res) {
			if (res.status == 200) {
				upload_iniconfig(filename);
			}
		}
	});
}

//ini配置文件处理
function upload_iniconfig(filename) {
	var dbus_post = {};
	dbus_post["merlinclash_action"] = db_merlinclash["merlinclash_action"] = "28"
	dbus_post["merlinclash_uploadininame"] = db_merlinclash["merlinclash_uploadininame"] = filename;
	push_data("clash_local_inifile_upload.sh", "28",  dbus_post);
	E('clashinifile_info').style.display = "block";
	//20200713
	yaml_select();
}
//------------------------------------------本地上传ini配置 结束------------------------------------//
//上传list文件到/tmp/upload文件夹
//------------------------------------------本地上传list文件 开始------------------------------------//
function upload_clashlistfile() {
	var filename = $("#clashlistfile").val();
	filename = filename.split('\\');
	filename = filename[filename.length - 1];
	var filelast = filename.split('.');
	filelast = filelast[filelast.length - 1];
	if (filelast != "list") {
		alert('上传文件格式非法！只支持上传list后缀的文件');
		return false;
	}
	E('clashlistfile_info').style.display = "none";
	var formData = new FormData();	
	formData.append(filename, document.getElementById('clashlistfile').files[0]);
	$.ajax({
		url: '/_upload',
		type: 'POST',
		cache: false,
		data: formData,
		processData: false,
		contentType: false,
		complete: function(res) {
			if (res.status == 200) {
				upload_listconfig(filename);
			}
		}
	});
}

//ini配置文件处理
function upload_listconfig(filename) {
	var dbus_post = {};
	dbus_post["merlinclash_action"] = db_merlinclash["merlinclash_action"] = "29"
	dbus_post["merlinclash_uploadlistfile"] = db_merlinclash["merlinclash_uploadlistfile"] = filename;
	push_data("clash_local_listfile_upload.sh", "29",  dbus_post);
	E('clashlistfile_info').style.display = "block";
}
//------------------------------------------本地上传list文件 结束------------------------------------//
//上传配置文件到/tmp/upload文件夹
//------------------------------------------本地上传配置 开始------------------------------------//
function upload_clashconfig() {
	var filename = $("#clashconfig").val();
	filename = filename.split('\\');
	filename = filename[filename.length - 1];
	var filelast = filename.split('.');
	filelast = filelast[filelast.length - 1];
	if (filelast != "yaml") {
		alert('上传文件格式非法！只支持上传yaml后缀的配置文件');
		return false;
	}
	E('clashconfig_info').style.display = "none";
	var formData = new FormData();
	
	formData.append(filename, document.getElementById('clashconfig').files[0]);

	$.ajax({
		url: '/_upload',
		type: 'POST',
		cache: false,
		data: formData,
		processData: false,
		contentType: false,
		complete: function(res) {
			if (res.status == 200) {
				upload_config(filename);
			}
		}
	});
}

//配置文件处理
function upload_config(filename) {
	var dbus_post = {};
	dbus_post["merlinclash_action"] = db_merlinclash["merlinclash_action"] = "3"
	dbus_post["merlinclash_uploadfilename"] = db_merlinclash["merlinclash_uploadfilename"] = filename;
	push_data("clash_config.sh", "upload",  dbus_post);
	E('clashconfig_info').style.display = "block";
	//20200713
	yaml_select();
}
//------------------------------------------本地上传配置 结束------------------------------------//
//------------------------------------------上传HOST 开始---------------------------------------//
function upload_clashhost() {
	var filename = $("#clashhost").val();
	filename = filename.split('\\');
	filename = filename[filename.length - 1];
	var filelast = filename.split('.');
	filelast = filelast[filelast.length - 1];
	if (filelast != "yaml") {
		alert('上传文件格式非法！只支持上传yaml后缀的hosts文件');
		return false;
	}
	E('clashhost_upload').style.display = "none";
	var formData = new FormData();
	
	//filename_tmp="hosts.yaml"
	formData.append(filename, document.getElementById('clashhost').files[0]);

	$.ajax({
		url: '/_upload',
		type: 'POST',
		cache: false,
		data: formData,
		processData: false,
		contentType: false,
		complete: function(res) {
			if (res.status == 200) {
				upload_host(filename);
			}
		}
	});
}
function upload_host(filename) {
	var dbus_post = {};
	action = dbus_post["merlinclash_action"] = db_merlinclash["merlinclash_action"] = "22"
	dbus_post["merlinclash_uploadhost"] = db_merlinclash["merlinclash_uploadhost"] = filename;
	push_data("clash_local_host_upload.sh", action,  dbus_post);
	E('clashhost_upload').style.display = "block";
	//20210415
	host_select();
}
//------------------------------------------上传HOST 结束---------------------------------------//
function update_notice(int){
	if ( int == "1"){
		alert('无在线更新功能，请到频道下载新补丁');
		return false;
	}else if( int == "0"){
		alert('暂无新版本');
		return false;
	}else{
		alert('无在线更新功能，请到频道下载新版本');
		return false;
	}

}
function version_show() {
	if(!db_merlinclash["merlinclash_version_local"]) db_merlinclash["merlinclash_version_local"] = "0.0.0"
	$("#merlinclash_version_show").html("<a class='hintstyle'><i>当前版本：" + db_merlinclash['merlinclash_version_local'] + "-" + db_merlinclash['merlinclash_patch_version']+ "</i></a>");
	$("#merlinclash_core_version").html("<span>clash：" + db_merlinclash['merlinclash_clash_version'] + " | UnblockNeteaseMusic：" + db_merlinclash['merlinclash_UnblockNeteaseMusic_version'] + " | koolproxy：" + db_merlinclash['merlinclash_koolproxy_version'] + " </span></div></td>");
	var raw_url=""
	if(db_merlinclash["merlinclash_flag"] == "HND" && db_merlinclash["merlinclash_flag2"] == "HND2"){
		raw_url="https://raw.githubusercontent.com/flyhigherpi/merlinclash_qca/main/config.json.js"
	}else if(db_merlinclash["merlinclash_flag"] == "384"){
		raw_url="https://raw.githubusercontent.com/flyhigherpi/merlinclash_384/master/config.json.js"
	}else if(db_merlinclash["merlinclash_flag"] == "OTH"){
		raw_url="https://raw.githubusercontent.com/flyhigherpi/merlinclash_qca/main/config.json.js"
	}else if(db_merlinclash["merlinclash_flag"] == "HND" && db_merlinclash["merlinclash_flag2"] != "HND2"){
		raw_url="https://raw.githubusercontent.com/flyhigherpi/merlinclash_hnd/master/config.json.js"
	}
	$.ajax({
		url: raw_url,
		type: 'GET',
		dataType: 'json',
		success: function(res) {
			if (typeof(res["version"]) != "undefined" && res["version"].length > 0) {
				var str=db_merlinclash["merlinclash_version_local"];
				var mvl_tmp=str.lastIndexOf('\.');
				var mvl=str.substring(0,mvl_tmp);
				if(db_merlinclash["merlinclash_flag"] == "HND"){
					var mscversion=db_merlinclash["merlinclash_scrule_version"];
				}
				//console.log(parseInt(res["version"]));
				//console.log(parseInt(str));
				//if (versionCompare(res["version"], str)) {
				E("updateBtn").innerHTML = "<a type=" +"'button'" + "class=" +"'ss_btn'" +"style="+"'cursor:pointer'"+" onclick=" + "'update_notice(0)'" + ">版本检查" + "</a>";
				if(parseInt(res["version"]) > parseInt(str)){
					E("updateBtn").innerHTML = "<a type="+"'button'" + " class=" +"'ss_btn'" +"style="+"'cursor:pointer'"+"onclick=" + "'update_notice(2)'" + "><em style='color: gold;'>新版本：" + res.version + "</em></a>";	
					return true;
				}
				console.log(parseInt(res["version"]));
				console.log(parseInt(str));
				if(parseInt(res["version"]) < parseInt(str)){
					return true;
				}else{
					//console.log(res["patch_version"]);
					if (versionCompare(res["patch_version"], db_merlinclash["merlinclash_patch_version"])){ 
						E("updateBtn").innerHTML = "<a type="+"'button'" + " class=" +"'ss_btn'" +"style="+"'cursor:pointer'"+"onclick=" + "'update_notice(1)'" + "><em style='color: gold;'>新补丁：" + res.patch_version + "</em></a>";
						
					}
				}
				if(db_merlinclash["merlinclash_flag"] == "HND"){
					if (versionCompare(res["sc_version"], mscversion)) {
						$("#updatescBtn").html("<i>新版本,点我更新</i>");
					}
				}
				//if (versionCompare(res["com_version"], mcomversion)) {
				//	$("#updatecomBtn").html("<i>新版本,点我更新</i>");
				//}
				//if (versionCompare(res["game_version"], mgameversion)) {
				//	$("#updategameBtn").html("<i>新版本,点我更新</i>");
				//}
			}
		}
	});
}
function functioncheck(label) {
	var dbus_post = {};
	dbus_post[label] = db_merlinclash[label] = E(label).checked ? '1' : '0';
	var id = parseInt(Math.random() * 100000000);
	var postData = {"id": id, "method": "dummy_script.sh", "params":[], "fields": dbus_post};
	$.ajax({
		type: "POST",
		cache:false,
		url: "/_api/",
		data: JSON.stringify(postData),
		dataType: "json",
		error: function(xhr) {
			
		},
		success: function(response) {
			refreshpage();	
		}
	});	
}
function dnsfilechange() {
	var dbus_post = {};
	var dns_content = E("merlinclash_dns_edit_content1").value;
	var dns_base64 = "";
	if(dns_content != ""){
		if(dns_content.search(/^dns:/) >= 0){
			dns_base64 = Base64.encode(dns_content);
			dbus_post["merlinclash_dns_edit_content1"] = db_merlinclash["merlinclash_dns_edit_content1"] = dns_base64;
		}else{
			alert("dns区域内容有误，提交dns配置必须以dns:开头");
			return false;
		} 
	}else{
		alert("dns区域内容不能为空！！！");
		return false;
	}
	var id = parseInt(Math.random() * 100000000);
	var postData = {"id": id, "method": "clash_dnsfilechange.sh", "params":[], "fields": dbus_post};
	$.ajax({
		type: "POST",
		cache:false,
		url: "/_api/",
		data: JSON.stringify(postData),
		dataType: "json",
		error: function(xhr) {
			
		},
		success: function(response) {
			refreshpage();	
		}
	});
}
//script区域文本保存
function scriptchange() {
	var dbus_post = {};
	var script_content = E("merlinclash_script_edit_content1").value;
	var script_base64 = "";
	if(script_content != ""){
		if(script_content.search(/^script:/) >= 0){
			script_base64 = Base64.encode(script_content);
			dbus_post["merlinclash_script_edit_content1"] = db_merlinclash["merlinclash_script_edit_content1"] = script_base64;
		}else{
			alert("script区域内容有误，提交script配置必须以script:开头");
			return false;
		} 
	}else{
		dbus_post["merlinclash_script_edit_content1"] = db_merlinclash["merlinclash_script_edit_content1"] = " ";
	}
	var id = parseInt(Math.random() * 100000000);
	var postData = {"id": id, "method": "clash_scriptchange.sh", "params":[], "fields": dbus_post};
	$.ajax({
		type: "POST",
		cache:false,
		url: "/_api/",
		data: JSON.stringify(postData),
		dataType: "json",
		error: function(xhr) {
			
		},
		success: function(response) {
			refreshpage();	
		}
	});
}
//host区域文本保存
function hostchange(){
	//采取分段保存
	var dbus_post = {};	
	var str="";
	var n = 5000;
	var i = 0;
	var host_content = E("merlinclash_host_content1").value;
	if(host_content != ""){
		if(host_content.search(/^hosts:/) >= 0){
			str = Base64.encode(encodeURIComponent(host_content));
			for (l = str.length; i < l/n; i++) {
				var a = str.slice(n*i, n*(i+1));
				dbus_post["merlinclash_host_content1_" + i] = db_merlinclash["merlinclash_host_content1_" + i] = a;
			}
			dbus_post["merlinclash_host_content1_count"] = db_merlinclash["merlinclash_host_content1_count"] = i;
		}else{
			alert("host区域内容有误，提交host配置必须以hosts:开头");
			return false;
		} 
	}else{
		dbus_post["merlinclash_host_content1_0"] = db_merlinclash["merlinclash_host_content1_0"] = " ";
		dbus_post["merlinclash_host_content1_count"] = db_merlinclash["merlinclash_host_content1_count"] = 1;
	}
	var id = parseInt(Math.random() * 100000000);
	var postData = {"id": id, "method": "clash_hostchange.sh", "params":[], "fields": dbus_post};
	$.ajax({
		type: "POST",
		cache:false,
		url: "/_api/",
		data: JSON.stringify(postData),
		dataType: "json",
		error: function(xhr) {
			
		},
		success: function(response) {
			refreshpage();	
		}
	});
}
//网易云定时重启
function unblock_restartjob_save() {
	var dbus_post = {};
	var id = parseInt(Math.random() * 100000000);
	dbus_post["merlinclash_select_job"]	= db_merlinclash["merlinclash_select_job"] = E("merlinclash_select_job").value;
	dbus_post["merlinclash_select_day"]	= db_merlinclash["merlinclash_select_day"] = E("merlinclash_select_day").value;
	dbus_post["merlinclash_select_week"] = db_merlinclash["merlinclash_select_week"] = E("merlinclash_select_week").value;
	dbus_post["merlinclash_select_hour"] = db_merlinclash["merlinclash_select_hour"] = E("merlinclash_select_hour").value;
	dbus_post["merlinclash_select_minute"] = db_merlinclash["merlinclash_select_minute"] = E("merlinclash_select_minute").value;	 
	var postData = {"id": id, "method": "clash_unblock_restartjob.sh", "params":[], "fields": dbus_post};
	$.ajax({
		type: "POST",
		cache:false,
		url: "/_api/",
		data: JSON.stringify(postData),
		dataType: "json",
		error: function(xhr) {
			
		},
		success: function(response) {
			refreshpage();	
		}
	});
}
//定时订阅
function regular_subscribe_save() {
	var dbus_post = {};
	var id = parseInt(Math.random() * 100000000);
	dbus_post["merlinclash_select_regular_subscribe"]	= db_merlinclash["merlinclash_select_regular_subscribe"] = E("merlinclash_select_regular_subscribe").value;
	dbus_post["merlinclash_select_regular_day"]	= db_merlinclash["merlinclash_select_regular_day"] = E("merlinclash_select_regular_day").value;
	dbus_post["merlinclash_select_regular_week"] = db_merlinclash["merlinclash_select_regular_week"] = E("merlinclash_select_regular_week").value;
	dbus_post["merlinclash_select_regular_hour"] = db_merlinclash["merlinclash_select_regular_hour"] = E("merlinclash_select_regular_hour").value;
	dbus_post["merlinclash_select_regular_minute"] = db_merlinclash["merlinclash_select_regular_minute"] = E("merlinclash_select_regular_minute").value;	 
	dbus_post["merlinclash_select_regular_minute_2"] = db_merlinclash["merlinclash_select_regular_minute_2"] = E("merlinclash_select_regular_minute_2").value;
	var postData = {"id": id, "method": "clash_regular_subscribe.sh", "params":[], "fields": dbus_post};
	$.ajax({
		type: "POST",
		cache:false,
		url: "/_api/",
		data: JSON.stringify(postData),
		dataType: "json",
		error: function(xhr) {
			
		},
		success: function(response) {
			refreshpage();	
		}
	});
}

//定时重启
function clash_restart_save() {
	var dbus_post = {};
	var id = parseInt(Math.random() * 100000000);
	dbus_post["merlinclash_select_clash_restart"]	= db_merlinclash["merlinclash_select_clash_restart"] = E("merlinclash_select_clash_restart").value;
	dbus_post["merlinclash_select_clash_restart_day"]	= db_merlinclash["merlinclash_select_clash_restart_day"] = E("merlinclash_select_clash_restart_day").value;
	dbus_post["merlinclash_select_clash_restart_week"] = db_merlinclash["merlinclash_select_clash_restart_week"] = E("merlinclash_select_clash_restart_week").value;
	dbus_post["merlinclash_select_clash_restart_hour"] = db_merlinclash["merlinclash_select_clash_restart_hour"] = E("merlinclash_select_clash_restart_hour").value;
	dbus_post["merlinclash_select_clash_restart_minute"] = db_merlinclash["merlinclash_select_clash_restart_minute"] = E("merlinclash_select_clash_restart_minute").value;	 
	dbus_post["merlinclash_select_clash_restart_minute_2"] = db_merlinclash["merlinclash_select_clash_restart_minute_2"] = E("merlinclash_select_clash_restart_minute_2").value;
	var postData = {"id": id, "method": "clash_restart_regularly.sh", "params":[], "fields": dbus_post};
	$.ajax({
		type: "POST",
		cache:false,
		url: "/_api/",
		data: JSON.stringify(postData),
		dataType: "json",
		error: function(xhr) {
			
		},
		success: function(response) {
			refreshpage();	
		}
	});
}

//提交看门狗设置
function clash_watchdog_save() {
	var dbus_post = {};
	var id = parseInt(Math.random() * 100000000);
	dbus_post["merlinclash_watchdog"]	= db_merlinclash["merlinclash_watchdog"] = E("merlinclash_watchdog").checked ? '1' : '0';
	dbus_post["merlinclash_watchdog_delay_time"]	= db_merlinclash["merlinclash_watchdog_delay_time"] = E("merlinclash_watchdog_delay_time").value;
	var postData = {"id": id, "method": "clash_watchdog_enable.sh", "params":[], "fields": dbus_post};
	$.ajax({
		type: "POST",
		cache:false,
		url: "/_api/",
		data: JSON.stringify(postData),
		dataType: "json",
		error: function(xhr) {
			
		},
		success: function(response) {
			refreshpage();	
		}
	});
}
function unblock_restart() {
	var dbus_post = {};
	if(parseInt(db_merlinclash["merlinclash_UnblockNeteaseMusic_version"]) >= parseInt("0.2.5")){
		dbus_post["merlinclash_unblockmusic_platforms_numbers"] = db_merlinclash["merlinclash_unblockmusic_platforms_numbers"] = E("merlinclash_unblockmusic_platforms_numbers").value;
	}
	dbus_post["merlinclash_unblockmusic_endpoint"] = db_merlinclash["merlinclash_unblockmusic_endpoint"] = E("merlinclash_unblockmusic_endpoint").value;
	dbus_post["merlinclash_unblockmusic_musicapptype"] = db_merlinclash["merlinclash_unblockmusic_musicapptype"] = E("merlinclash_unblockmusic_musicapptype").value;
	dbus_post["merlinclash_unblockmusic_acl_default"] = db_merlinclash["merlinclash_unblockmusic_acl_default"] = E("merlinclash_unblockmusic_acl_default").value;
	dbus_post["merlinclash_unblockmusic_log"] = db_merlinclash["merlinclash_unblockmusic_log"] = E("merlinclash_unblockmusic_log").checked ? '1' : '0';	
	dbus_post["merlinclash_unblockmusic_vip"] = db_merlinclash["merlinclash_unblockmusic_vip"] = E("merlinclash_unblockmusic_vip").checked ? '1' : '0';	
	dbus_post["merlinclash_action"] = db_merlinclash["merlinclash_action"] = "8"
	var unplan = document.getElementsByName("unblockplan").innerHTML = getradioval(6);
	dbus_post["merlinclash_unblockmusic_unblockplan"] = db_merlinclash["merlinclash_unblockmusic_unblockplan"] = unplan;
	push_data("clash_config.sh", "unblockmusicrestart",  dbus_post);	
}
function savefile(){
	// collect basic data
	var params = ["merlinclash_koolproxy_mode", "merlinclash_koolproxy_reboot", "merlinclash_koolproxy_reboot_hour", "merlinclash_koolproxy_reboot_min", "merlinclash_koolproxy_reboot_inter_hour", "merlinclash_koolproxy_reboot_inter_min", "merlinclash_koolproxy_acl_method", "merlinclash_koolproxy_acl_default"];
	var params_chk = ["merlinclash_koolproxy_enable", "merlinclash_koolproxy_rule_enable_d1", "merlinclash_koolproxy_rule_enable_d2", "merlinclash_koolproxy_rule_enable_d3", "merlinclash_koolproxy_rule_enable_d4"];
	for (var i = 0; i < params.length; i++) {
		db_merlinclash[params[i]] = E(params[i]).value;
	}
	for (var i = 0; i < params_chk.length; i++) {
		db_merlinclash[params_chk[i]] = E(params_chk[i]).checked ? "1" : "0";
	}
	// collect value in user rule textarea
	db_merlinclash["merlinclash_koolproxy_custom_rule"] = Base64.encode(E("usertxt").value);
	// collect data from acl pannel
	if(E("KPYACL_table")){
		var tr = E("KPYACL_table").getElementsByTagName("tr");
		for (var i = 1; i < tr.length ; i++) {	
			if (E("merlinclash_koolproxy_acl_mode_" + i)){
				if(E("merlinclash_koolproxy_acl_ip_" + i).value != ""){
					db_merlinclash["merlinclash_koolproxy_acl_ip_" + i] = E("merlinclash_koolproxy_acl_ip_" + i).value;
				}else{
					db_merlinclash["merlinclash_koolproxy_acl_ip_" + i] = " ";
				}
				if(E("merlinclash_koolproxy_acl_mac_" + i).value != ""){
					db_merlinclash["merlinclash_koolproxy_acl_mac_" + i] = E("merlinclash_koolproxy_acl_mac_" + i).value;
				}else{
					db_merlinclash["merlinclash_koolproxy_acl_mac_" + i] = " ";
				}
				db_merlinclash["merlinclash_koolproxy_acl_name_" + i] = E("merlinclash_koolproxy_acl_name_" + i).value;
				db_merlinclash["merlinclash_koolproxy_acl_mode_" + i] = E("merlinclash_koolproxy_acl_mode_" + i).value;
			}else{
				
			}				
		}
	}else{

	}
	// collect data from rule pannel
	if(E("rule_table")){
		var tr = E("rule_table").getElementsByTagName("tr");
		for (var i = 1; i < tr.length ; i++) {	
			if (E("merlinclash_koolproxy_rule_enable_" + i)){
				db_merlinclash["merlinclash_koolproxy_rule_enable_" + i] = E("merlinclash_koolproxy_rule_enable_" + i).checked ? "1" : "0";
			}else{
				
			}				
		}
	}else{

	}
	var sourceList="";
	if(E("merlinclash_koolproxy_rule_enable_d1").checked == true){
		sourceList += "1|koolproxy.txt||静态规则>"
	}else{
		sourceList += "0|koolproxy.txt||静态规则>"
	}
	if(E("merlinclash_koolproxy_rule_enable_d2").checked == true){
		sourceList += "1|daily.txt||每日规则>"
	}else{
		sourceList += "0|daily.txt||每日规则>"
	}
	if(E("merlinclash_koolproxy_rule_enable_d3").checked == true){
		sourceList += "1|kp.dat||视频规则>"
	}else{
		sourceList += "0|kp.dat||视频规则>"
	}
	if(E("merlinclash_koolproxy_rule_enable_d4").checked == true){
		sourceList += "1|user.txt||自定规则>"
	}else{
		sourceList += "0|user.txt||自定规则>"
	}
	//maxid = parseInt($("#rule_table > tbody > tr:eq(-2) > td:nth-child(1) > input").attr("id").split("_")[3]);
	var maxid = E("rule_table").getElementsByTagName("tr");
	for ( var i = 1; i <= maxid.length; ++i ) {
		if (E("merlinclash_koolproxy_rule_enable_" + i)){
			sourceList += E("merlinclash_koolproxy_rule_enable_" + i).checked ? "1" : "0";
			sourceList += "|"
			sourceList += E("merlinclash_koolproxy_rule_enable_" + i).innerHTML
			sourceList += "|"
			sourceList += E("merlinclash_koolproxy_rule_enable_" + i).innerHTML
			sourceList += "|"
			sourceList += E("merlinclash_koolproxy_rule_enable_" + i).innerHTML
			sourceList += ">"
		}
	}
	db_merlinclash["merlinclash_koolproxy_sourcelist"] = sourceList;
	//post data
	push_data("clash_config.sh", "koolproxyrestart",  db_merlinclash);
}
function createcert(action) {
	var dbus_post = {};
	var id = parseInt(Math.random() * 100000000);
	dbus_post["merlinclash_action"] = db_merlinclash["merlinclash_action"] = action;
	push_data("clash_unblockmusic_createcrt.sh", action, dbus_post);
}
function downloadcert() {
	var dbus_post = {};
	var id = parseInt(Math.random() * 100000000);
	var postData = {"id": id, "method": "clash_unblockmusic_cert.sh", "params":[], "fields": dbus_post};
	var cert=""
	$.ajax({
			type: "POST",
			cache:false,
			url: "/_api/",
			data: JSON.stringify(postData),
			dataType: "json",
			success: function(response) {
				cert = response.result;
				download_cert(cert);
			}
	});	
}
function download_cert(cert) {
	var a= "http://"+window.location.hostname+"/_temp/"+cert;
	var downloadA = document.createElement('a');
	var josnData = {};
	var blob = new Blob([JSON.stringify(josnData)],{type : 'application/json'});
	downloadA.href = a
	downloadA.download = cert;
	downloadA.click();
	window.URL.revokeObjectURL(downloadA.href);
}
function geoip_update(action){
	var dbus_post = {};
	var date = new Date();
    var seperator1 = "-";
    var seperator2 = ":";
    var month = date.getMonth() + 1;
    var strDate = date.getDate();
    if (month >= 1 && month <= 9) {
        month = "0" + month;
    }
    if (strDate >= 0 && strDate <= 9) {
        strDate = "0" + strDate;
    }
    var currentdate = date.getFullYear() + seperator1 + month + seperator1 + strDate
            + " " + date.getHours() + seperator2 + date.getMinutes()
            + seperator2 + date.getSeconds();
	require(['/res/layer/layer.js'], function(layer) {
		layer.confirm('<li>你确定要更新GeoIP数据库吗？</li>', {
			shade: 0.8,
		}, function(index) {
			$("#log_content3").attr("rows", "20");
			dbus_post["merlinclash_action"] = db_merlinclash["merlinclash_action"] = action;
			dbus_post["merlinclash_updata_date"] = db_merlinclash["merlinclash_updata_date"] = currentdate;
			dbus_post["merlinclash_geoip_type"] = db_merlinclash["merlinclash_geoip_type"] = E("merlinclash_geoip_type").value;
			push_data("clash_update_ipdb.sh", action, dbus_post);
			E("geoip_updata_date").innerHTML = "<span style='color: gold'>上次更新时间："+db_merlinclash["merlinclash_updata_date"]+"</span>";
			layer.close(index);
			return true;
			
		}, function(index) {
			layer.close(index);
			return false;
		});
	});
}
function chnroute_update(action){
	var dbus_post = {};
	var date = new Date();
    var seperator1 = "-";
    var seperator2 = ":";
    var month = date.getMonth() + 1;
    var strDate = date.getDate();
    if (month >= 1 && month <= 9) {
        month = "0" + month;
    }
    if (strDate >= 0 && strDate <= 9) {
        strDate = "0" + strDate;
    }
    var currentdate = date.getFullYear() + seperator1 + month + seperator1 + strDate
            + " " + date.getHours() + seperator2 + date.getMinutes()
            + seperator2 + date.getSeconds();
	require(['/res/layer/layer.js'], function(layer) {
		layer.confirm('<li>你确定要更新大陆白名单规则吗？</li>', {
			shade: 0.8,
		}, function(index) {
			$("#log_content3").attr("rows", "20");
			dbus_post["merlinclash_action"] = db_merlinclash["merlinclash_action"] = action;
			dbus_post["merlinclash_chnrouteupdate_date"] = db_merlinclash["merlinclash_chnrouteupdate_date"] = currentdate;
			push_data("clash_update_chnroute.sh", action, dbus_post);
			E("chnroute_updata_date").innerHTML = "<span style='color: gold'>上次更新时间："+db_merlinclash["merlinclash_chnrouteupdate_date"]+"</span>";
			layer.close(index);
			return true;
			
		}, function(index) {
			layer.close(index);
			return false;
		});
	});
}
function sc_update(action) {
	var dbus_post = {};
	require(['/res/layer/layer.js'], function(layer) {
		layer.confirm('<li>你确定要更新subconverter规则文件吗？</li>', {
			shade: 0.8,
		}, function(index) {
			$("#log_content3").attr("rows", "20");
			dbus_post["merlinclash_action"] = db_merlinclash["merlinclash_action"] = action;
			push_data("clash_update_sc.sh", action, dbus_post);
			layer.close(index);
			return true;
			
		}, function(index) {
			layer.close(index);
			return false;
		});
	});
}
function doalert(id){
  if(this.checked) {
     alert('checked');
  }else{
     alert('unchecked');
  }
}
function clash_getversion(action) {
	var dbus_post = {};
	dbus_post["merlinclash_action"] = db_merlinclash["merlinclash_action"] = action;
	push_data("clash_get_binary_history.sh", action, dbus_post);
}
function clash_replace(action) {
	if(!$.trim($('#merlinclash_clashbinarysel').val())){
		alert("请选择二进制版本");
		return false;
	}
	var dbus_post = {};
	dbus_post["merlinclash_action"] = db_merlinclash["merlinclash_action"] = action;
	dbus_post["merlinclash_clashbinarysel"] = db_merlinclash["merlinclash_clashbinarysel"] = E("merlinclash_clashbinarysel").value;
	push_data("clash_get_binary_history.sh", action, dbus_post);
}
//----------------下拉框获取host文件名BEGIN--------------------------
function host_select(){	
	var id = parseInt(Math.random() * 100000000);
	var postData = {"id": id, "method": "clash_gethostsel.sh", "params":[], "fields": ""};
	$.ajax({
		type: "POST",
		cache:false,
		url: "/_api/",
		data: JSON.stringify(postData),
		dataType: "json",
		success: function(response) {
			if(response.result == id){
				host_select_get();
			}
		}
	});
}

function host_select_get() {
	
	$.ajax({
		url: '/_temp/hosts.txt',		
		type: 'GET',
		cache:false,
		dataType: 'text',
		success: function(response) {
			//按换行符切割
			var arr = response.split("\n");
			Myhostselect(arr);
		}
	});
}
var hostcounts;
hostcounts=0;
function Myhostselect(arr){
	var i;
	hostcounts=arr.length;
	var hostlist = arr;  
	for(i=0;i<hostlist.length-1;i++){
		var a=hostlist[i];
		if(a == db_merlinclash["merlinclash_hostsel"]){//如果是用户选择的，则变成被选中状态
			$("#merlinclash_hostsel").append("<option value=" + a + " selected>" + a + "</option>")
		}else{
			$("#merlinclash_hostsel").append("<option value=" + a + ">" + a + "</option>");
		}
	}
}
//----------------下拉框获取host文件名 END --------------------------
//----------------下拉框获取配置文件名BEGIN--------------------------
function yaml_select(){	
	var id = parseInt(Math.random() * 100000000);
	var postData = {"id": id, "method": "clash_getyamls.sh", "params":[], "fields": ""};
	$.ajax({
		type: "POST",
		cache:false,
		url: "/_api/",
		data: JSON.stringify(postData),
		dataType: "json",
		success: function(response) {
			if(response.result == id){
				yaml_select_get();
				yamlcus_select_get();
				yamlcuslist_select_get();
			}
		}
	});
}

function yaml_select_get() {	
	$.ajax({
		url: '/_temp/yamls.txt',		
		type: 'GET',
		cache:false,
		dataType: 'text',
		success: function(response) {
			//按换行符切割
			var arr = response.split("\n");
			Myselect(arr);
		}
	});
}
var counts;
counts=0;
function Myselect(arr){
	var i;
	counts=arr.length;
	var yamllist = arr; 
	$("#merlinclash_yamlsel").append("<option value=''>--请选择--</option>");
	$("#merlinclash_delyamlsel").append("<option value=''>--请选择--</option>");
	
	for(i=0;i<yamllist.length-1;i++){
		var a=yamllist[i];
		//$("#merlinclash_yamlsel").append("<option value='"+a+"' >"+a+"</option>");
		if(a == db_merlinclash["merlinclash_yamlsel"]){//如果是用户选择的，则变成被选中状态
			$("#merlinclash_yamlsel").append("<option value=" + a + " selected>" + a + "</option>")
		}else{
			$("#merlinclash_yamlsel").append("<option value=" + a + ">" + a + "</option>");
		}
		$("#merlinclash_delyamlsel").append("<option value=" + a + ">" + a + "</option>");
	}
}
function yamlcus_select_get() {
	
	$.ajax({
		url: '/_temp/yamlscus.txt',		
		type: 'GET',
		cache:false,
		dataType: 'text',
		success: function(response) {
			//按换行符切割
			var arr = response.split("\n");
			Mycusselect(arr);
		}
	});
}
var countscus;
countscus=0;
function Mycusselect(arr){
	var i;
	countscus=arr.length;
	var yamlcuslist = arr;  
	$("#merlinclash_delinisel").append("<option value=''>--请选择--</option>");	
	for(i=0;i<yamlcuslist.length-1;i++){
		var a=yamlcuslist[i];
		$("#merlinclash_acl4ssrsel_cus").append("<option value='"+a+"' >"+a+"</option>");
		$("#merlinclash_delinisel").append("<option value='"+a+"' >"+a+"</option>");
	}
}
function yamlcuslist_select_get() {
	
	$.ajax({
		url: '/_temp/yamlscuslist.txt',		
		type: 'GET',
		cache:false,
		dataType: 'text',
		success: function(response) {
			//按换行符切割
			var arr = response.split("\n");
			Mycuslistselect(arr);
		}
	});
}
var countscuslist;
countscuslist=0;
function Mycuslistselect(arr){
	var i;
	countscuslist=arr.length;
	var yamlcuslist = arr;  
	$("#merlinclash_dellistsel").append("<option value=''>--请选择--</option>");	
	for(i=0;i<yamlcuslist.length-1;i++){
		var a=yamlcuslist[i];
		$("#merlinclash_dellistsel").append("<option value='"+a+"' >"+a+"</option>");
	}
}
//----------------下拉框获取配置文件名END--------------------------
//----------------下拉框获取clash版本号BEGIN--------------------------
function clashbinary_select(){	
	var id = parseInt(Math.random() * 100000000);
	var postData = {"id": id, "method": "clash_getclashbinary.sh", "params":[], "fields": ""};
	$.ajax({
		type: "POST",
		cache:false,
		url: "/_api/",
		data: JSON.stringify(postData),
		dataType: "json",
		success: function(response) {
			if(response.result == id){
				clashbinary_select_get();
				
			}
		}
	});
}

function clashbinary_select_get() {
	
	$.ajax({
		url: '/_temp/clash_binary_history.txt',		
		type: 'GET',
		cache:false,
		dataType: 'text',
		success: function(response) {
			//按换行符切割
			var arr = response.split("\n");
			Myclashbinary(arr);
		}
	});
}
var binarys;
binarys=0;
function Myclashbinary(arr){
	var k;
	binarys=arr.length;
	var binarylist = arr;  	
	$("#merlinclash_clashbinarysel").append("<option value=''>---------请选择---------</option>");
	for(k=0;k<binarylist.length;k++){
		var a=binarylist[k];
		$("#merlinclash_clashbinarysel").append("<option value='"+a+"' >"+a+"</option>");
	}
}
//----------------下拉框获取clash版本号END--------------------------
//----------------------------proxy-group 下拉框部分代码BEGIN-------------------------//
function proxygroup_select(){
	var id = parseInt(Math.random() * 100000000);
	var postData = {"id": id, "method": "clash_getproxygroup.sh", "params":[], "fields": ""};
	$.ajax({
		type: "POST",
		cache:false,
		url: "/_api/",
		data: JSON.stringify(postData),
		dataType: "json",
		success: function(response) {
			if(response.result == id){
				setTimeout("proxygroup_select_get();", 300);
			}
		}
	});
}
function proxygroup_select_get() {
	$.ajax({
		url: '/_temp/proxygroups.txt',
		type: 'GET',
		cache:false,
		dataType: 'text',
		success: function(response) {
			//按换行符切割
			var arr = response.split("\n");
			Mypgselect(arr);
		}
	});
}
var pgcounts;
pgcounts=0;
function Mypgselect(arr){
	var i;
	pgcounts=arr.length;
	var pglist = arr;  
	   	$("#merlinclash_acl_lianjie").append("<option value=''>--请选择--</option>");
	for(i=0;i<pglist.length-1;i++){
		var a=pglist[i];
		$("#merlinclash_acl_lianjie").append("<option value='"+a+"' >"+a+"</option>");
	}
}
//----------------------------proxy-group下拉框部分代码END--------------------------//
//----------------------------KoolProxy代码部分BEGIN-------------------------------//
function getKPYACLConfigs() {
	var dict = {};
	for (var field in db_kpyacl) {
		names = field.split("_");
		dict[names[names.length - 1]] = 'ok';
	}
	kpyacl_confs = {};
	var p = "merlinclash_koolproxy_acl";
	var params = ["ip", "name", "mode"];
	for (var field in dict) {
		var obj = {};
		if (typeof db_kpyacl[p + "_mac_" + field] == "undefined") {
			obj["mac"] = '';
		} else {
			obj["mac"] = db_kpyacl[p + "_mac_" + field];
		}
		for (var i = 0; i < params.length; i++) {
			var ofield = p + "_" + params[i] + "_" + field;
			if (typeof db_kpyacl[ofield] == "undefined") {
				obj = null;
				break;
			}
			obj[params[i]] = db_kpyacl[ofield];
		}
		if (obj != null) {
			var node_a = parseInt(field);
			if (node_a > kpyacl_node_max) {
				kpyacl_node_max = node_a;
			}
			obj["kpyacl_node"] = field;
			kpyacl_confs[field] = obj;
		}
	}
	return kpyacl_confs;
}

function addKPYTr() {
	if(!$.trim($('#merlinclash_koolproxy_acl_ip').val()) && !$.trim($('#merlinclash_koolproxy_acl_mac').val())){
		alert("主机IP地址/主机MAC地址不能同时为空！");
		return false;
	}
	if(!$.trim($('#merlinclash_koolproxy_acl_name').val())){
		alert("主机别名不能为空！");
		return false;
	}
	var kpyacls = {};
	var p = "merlinclash_koolproxy_acl";
	kpyacl_node_max += 1;
	var params = ["ip", "name", "mac", "mode"];
	for (var i = 0; i < params.length; i++) {
		kpyacls[p + "_" + params[i] + "_" + kpyacl_node_max] = $('#' + p + "_" + params[i]).val();
		if($('#' + p + "_" + params[i]).val() == ""){
			kpyacls[p + "_" + params[i] + "_" + kpyacl_node_max] = " ";
		}
	}

	var id = parseInt(Math.random() * 100000000);
	var postData = {"id": id, "method": "dummy_script.sh", "params":[2], "fields": kpyacls};
	$.ajax({
		type: "POST",
		cache:false,
		url: "/_api/",
		data: JSON.stringify(postData),
		dataType: "json",
		success: function(response) {
			if (response.result == id){
				refresh_kpyacl_table();
				E("merlinclash_koolproxy_acl_name").value = "";
				E("merlinclash_koolproxy_acl_ip").value = "";
				E("merlinclash_koolproxy_acl_mac").value = "";
				E("merlinclash_koolproxy_acl_mode").value = "1";
			}
		}
	});
	kpyaclid = 0;
}

function delKPYTr(o) {
	var id = $(o).attr("id");
	var ids = id.split("_");
	var p = "merlinclash_koolproxy_acl";
	id = ids[ids.length - 1];
	var kpyacls = {};
	var params = ["ip", "name", "mac", "mode"];
	for (var i = 0; i < params.length; i++) {
		db_merlinclash[p + "_" + params[i] + "_" + id] = kpyacls[p + "_" + params[i] + "_" + id] = "";
	}
	var id = parseInt(Math.random() * 100000000);
	var postData = {"id": id, "method": "dummy_script.sh", "params":[2], "fields": kpyacls};
	$.ajax({
		type: "POST",
		cache:false,
		url: "/_api/",
		data: JSON.stringify(postData),
		dataType: "json",
		success: function(response) {
			refresh_kpyacl_table();
		}
	});
}

function refresh_kpyacl_table(q) {
	$.ajax({
		type: "GET",
		url: "/_api/merlinclash_koolproxy_acl",
		dataType: "json",
		async:false,
		success: function(data){
			db_kpyacl=data.result[0];
			refresh_kpyacl_html();
			for (var i = 1; i < kpyacl_node_max + 1; i++) {
				$('#merlinclash_koolproxy_acl_mode_' + i).val(db_kpyacl["merlinclash_koolproxy_acl_mode_" + i]);
				$('#merlinclash_koolproxy_acl_name_' + i).val(db_kpyacl["merlinclash_koolproxy_acl_name_" + i]);
			}
			if (typeof db_kpyacl["merlinclash_koolproxy_acl_default"] !== "undefined"){
				$('#merlinclash_koolproxy_acl_default').val(db_kpyacl["merlinclash_koolproxy_acl_default"]);
			}else{
				$('#merlinclash_koolproxy_acl_default').val("1");
			}

	  	}
	});
}

function refresh_kpyacl_html() {
	kpyacl_confs = getKPYACLConfigs();
	var n = 0;
	for (var i in kpyacl_confs) {
		n++;
	}
	var code = '';
	code += '<table width="750px" border="0" align="center" cellpadding="4" cellspacing="0" class="FormTable_table kpyacl_lists" style="margin:-1px 0px 0px 0px;">'
	code += '<tr>'
	code += '<th width="180px" style="text-align: center; vertical-align: middle;">主机IP地址</th>'
	code += '<th width="160px" style="text-align: center; vertical-align: middle;">mac地址</th>'
	code += '<th width="160px" style="text-align: center; vertical-align: middle;">主机别名</th>'
	code += '<th width="160px" style="text-align: center; vertical-align: middle;">访问控制</th>'
	code += '<th width="70px" style="text-align: center; vertical-align: middle;">添加/删除</th>'
	code += '</tr>'
	code += '</table>'										
	// acl table input area
	code += '<table id="KPYACL_table" width="750px" border="0" align="center" cellpadding="4" cellspacing="0" class="list_table kpyacl_lists" style="margin:-1px 0px 0px 0px;">'
		code += '<tr>'
	//主机ip
			code += '<td width="180px">'
			code += '<input type="text" maxlength="50" class="input_15_table" id="merlinclash_koolproxy_acl_ip" align="left" onkeypress="return validator.isIPAddr(this, event)" style="float:center;width:145px;text-align:center" autocomplete="off" onClick="hideKPYClients_Block();" autocorrect="off" autocapitalize="off">'
			code += '<img id="pull_arrow" height="14px;" src="images/arrow-down.gif" style="float:right;" align="right" onclick="pullKPYLANIPList(this);" title="<#select_IP#>">'
			code += '<div id="KPYClientList_Block" class="clientlist_dropdown" style="margin-left:2px;width:235px;"></div>'
			code += '</td>'
	//主机mac
			code += '<td width="160px">'
			code += '<input type="text" id="merlinclash_koolproxy_acl_mac" name="merlinclash_koolproxy_acl_mac" class="input_15_table" maxlength="50" style="width:140px;text-align:center" placeholder="" />'
			code += '</td>'
	//主机别名
			code += '<td width="160px">'
			code += '<input type="text" id="merlinclash_koolproxy_acl_name" name="merlinclash_koolproxy_acl_name" class="input_15_table" maxlength="50" style="width:140px;text-align:center" placeholder="" />'
			code += '</td>'
	//访问控制
			code += '<td width="160px">'
			code += '<select id="merlinclash_koolproxy_acl_mode" name="merlinclash_koolproxy_acl_mode" style="width:140px;margin:-1px 0px 0px 2px;text-align:middle;padding-left: 0px;" class="input_option">'
			code +=	'<option value="1">http only</option>'
			code +=	'<option value="2">http + https</option>'	
			code +=	'<option value="0">不过滤</option>'																																				
			code +=	'</select>'
			code += '</td>'
	// add/delete 按钮
			code += '<td width="66px">'
			code += '<input style="margin-left: 6px;margin: -3px 0px -5px 6px;" type="button" class="add_btn" onclick="addKPYTr()" value="" />'
			code += '</td>'
		code += '</tr>'														
	for (var field in kpyacl_confs) {
		var kpyc = kpyacl_confs[field];
		code = code + '<tr>';
		code = code + '<td>';
		code = code + '<input type="text" placeholder="" id="merlinclash_koolproxy_acl_ip_' + kpyc["kpyacl_node"] + '" name="merlinclash_koolproxy_acl_ip_' + kpyc["kpyacl_node"] + '" class="input_15_table" maxlength="50" style="width:140px; text-align:center"" value="' + kpyc["ip"] + '" />';
		code = code + '</td>';
		code = code + '<td>';
		code = code + '<input type="text" placeholder="" id="merlinclash_koolproxy_acl_mac_' + kpyc["kpyacl_node"] + '" name="merlinclash_koolproxy_acl_mac_' + kpyc["kpyacl_node"] + '" class="input_15_table" maxlength="50" style="width:140px; text-align:center"" value="' + kpyc["mac"] + '" />';
		code = code + '</td>';
		code = code + '<td>';
		code = code + '<input type="text" placeholder="" id="merlinclash_koolproxy_acl_name_' + kpyc["kpyacl_node"] + '" name="merlinclash_koolproxy_acl_name_' + kpyc["kpyacl_node"] + '" class="input_15_table" maxlength="50" style="width:140px; text-align:center"" value="' + kpyc["name"] + '" />';
		code = code + '</td>';
		code = code + '<td>';
		code = code + '<select id="merlinclash_koolproxy_acl_mode_' + kpyc["kpyacl_node"] + '" name="merlinclash_koolproxy_acl_mode_' + kpyc["kpyacl_node"] + '" style="width:140px;margin:-1px 0px 0px 2px;" class="input_option">';
		code = code + '<option value="1">http only</option>';
		code = code + '<option value="2">http + https</option>';
		code = code + '<option value="0">不过滤</option>';
		code = code + '</select>'
		code = code + '</td>';
		code = code + '<td>';
		code = code + '<input style="margin: -3px 0px -5px 6px;" id="kpyacl_node_' + kpyc["kpyacl_node"] + '" class="remove_btn" type="button" onclick="delKPYTr(this);" value="">'
		code = code + '</td>';
		code = code + '</tr>';
	}
	code = code + '<tr>';
	if (n == 0) {
		code = code + '<td style="text-align: center;">所有主机</td>';
	} else {
		code = code + '<td style="text-align: center;">其它主机</td>';
	}
	code = code + '<td style="text-align: center;">缺省规则</td>';
	code = code + '<td style="text-align: center;">缺省规则</td>';
	code = code + '<td>';
	code = code + '<select id="merlinclash_koolproxy_acl_default" name="merlinclash_koolproxy_acl_default" style="width:140px;margin:-1px 0px 0px 2px;" class="input_option";">';
	code = code + '<option value="1" selected>http only</option>';
	code = code + '<option value="2">http + https</option>';
	code = code + '<option value="0">不过滤</option>';
	code = code + '</select>';
	code = code + '</td>';
	code = code + '<td>';
	code = code + '</td>';
	code = code + '</tr>';
	code += '</table>';

	$(".kpyacl_lists").remove();
	$('#merlinclash_KPYACL_table').after(code);

	showDropdownClientList('setkpyClientIP', 'ip>mac', 'all', 'KPYClientList_Block', 'pull_arrow', 'online');

}

function getkpyruleConfigs() {
	var dict = {};
	for (var field in db_kpyrule) {
		names = field.split("_");
		dict[names[names.length - 1]] = 'ok';
	}
	rule_confs = {};
	var p = "merlinclash_koolproxy_rule";
	var params = ["enable", "file", "addr", "note"];
	for (var field in dict) {
		var obj = {};

		for (var i = 0; i < params.length; i++) {
			var ofield = p + "_" + params[i] + "_" + field;
			if (typeof db_kpyrule[ofield] == "undefined") {
				obj = null;
				break;
			}
			obj[params[i]] = db_kpyrule[ofield];
		}
		if (obj != null) {
			var node_a = parseInt(field);
			if (node_a > rule_node_max) {
				rule_node_max = node_a;
			}
			obj["rule_node"] = field;
			rule_confs[field] = obj;
		}
	}
	return rule_confs;
}

function add_kpyrule_Tr() {
	var rules = {};
	var p = "merlinclash_koolproxy_rule";
	rule_node_max += 1;

	if (edit_falg){
			console.log("333", edit_falg)
		var add_nu = edit_falg
	}else{
		var add_nu = rule_node_max
	}
	
	var params = ["file", "addr", "note"];
	for (var i = 0; i < params.length; i++) {
		rules[p + "_" + params[i] + "_" + add_nu] = $('#' + p + "_" + params[i]).val();
	}
	rules["merlinclash_koolproxy_rule_enable_" + add_nu] = E("merlinclash_koolproxy_rule_enable").checked ? "1" : "0";

	var id = parseInt(Math.random() * 100000000);
	var postData = {"id": id, "method": "dummy_script.sh", "params":[2], "fields": rules};
	$.ajax({
		type: "POST",
		cache:false,
		url: "/_api/",
		data: JSON.stringify(postData),
		dataType: "json",
		success: function(response) {
			if (response.result == id){
				refresh_kpyrule_table();
				E("merlinclash_koolproxy_rule_enable").checked = false;
				E("merlinclash_koolproxy_rule_file").value = "";
				E("merlinclash_koolproxy_rule_addr").value = "";
				E("merlinclash_koolproxy_rule_note").value = "";
			}
		}
	});
	edit_falg=""
}

function del_kpyrule_Tr(o) {
	var id = $(o).attr("id");
	var ids = id.split("_");
	var p = "merlinclash_koolproxy_rule";
	id = ids[ids.length - 1];
	var rules = {};
	var params = ["enable", "file", "addr", "note"];
	for (var i = 0; i < params.length; i++) {
		rules[p + "_" + params[i] + "_" + id] = "";
	}
	var id = parseInt(Math.random() * 100000000);
	var postData = {"id": id, "method": "dummy_script.sh", "params":[2], "fields": rules};
	$.ajax({
		type: "POST",
		cache:false,
		url: "/_api/",
		data: JSON.stringify(postData),
		dataType: "json",
		success: function(response) {
			refresh_kpyrule_table();
		}
	});
}

function edit_kpyrule_Tr(o) {
	var id = $(o).attr("id");
	var ids = id.split("_");
	var p = "merlinclash_koolproxy_rule";
	id = ids[ids.length - 1];
	console.log(id)
	var params = ["file", "addr", "note"];
	for (var i = 0; i < params.length; i++) {
		E(p +"_" + params[i]).value = db_kpyrule[p +"_" + params[i] + "_" + id];
	}
	E("merlinclash_koolproxy_rule_enable").checked = db_kpyrule["merlinclash_koolproxy_rule_enable_" + id ] == 1
	edit_falg=id
}

function refresh_kpyrule_table() {
	$.ajax({
		type: "GET",
		url: "/_api/merlinclash_koolproxy_",
		dataType: "json",
		async:false,
		success: function(response){
			db_kpyrule=response.result[0];
			
			$("#rule_table").find("tr:gt(5):lt(-1)").remove();
			$('#rule_table tr:eq(5)').after(refresh_kpyrule_html());
			for (var i = 1; i < rule_node_max + 1; i++) {
				if (db_kpyrule["merlinclash_koolproxy_rule_enable_" + i]){
					E("merlinclash_koolproxy_rule_enable_" + i).checked = (db_kpyrule["merlinclash_koolproxy_rule_enable_" + i] == 1);
				}
			}
	  	}
	});
}

function refresh_kpyrule_html() {
	rule_confs = getkpyruleConfigs();
	var n = 0;
	for (var i in rule_confs) {
		n++;
	}
	var code = '';
	for (var field in rule_confs) {
		var rlc = rule_confs[field];
		code = code + '<tr calss="added">';
		code = code + '<td style="text-align:center;">';
		code = code + '<input type="checkbox" id="merlinclash_koolproxy_rule_enable_' + rlc["rule_node"] + '" name="merlinclash_koolproxy_rule_enable_' + rlc["rule_node"] + '" />';
		code = code + '</td>';
		code = code + '<td id="merlinclash_koolproxy_rule_file_' + rlc["rule_node"] + '">';
		code = code + rlc["file"];
		code = code + '</td>';
		code = code + '<td id="merlinclash_koolproxy_rule_addr_' + rlc["rule_node"] + '">';
		code = code + rlc["addr"];
		code = code + '</td>';
		code = code + '<td id="merlinclash_koolproxy_rule_note_' + rlc["rule_node"] + '" style="text-align:center;">';
		code = code + rlc["note"];
		code = code + '</td>';
		code = code + '<td id="merlinclash_koolproxy_rule_nu_' + rlc["rule_node"] + '">';
		code = code + '</td>';
		code = code + '<td>';
		code = code + '<input id="merlinclash_koolproxy_rule_edit_' + rlc["rule_node"] + '" style="margin-left: 6px;margin: -3px 0px -5px 6px;" type="button" class="edit_btn" onclick="edit_kpyrule_Tr(this)"/>'
		code = code + '</td>';
		code = code + '<td>';
		code = code + '<input id="merlinclash_koolproxy_rule_del_' + rlc["rule_node"] + '" style="margin-left: 6px;margin: -3px 0px -5px 6px;" type="button" class="remove_btn" onclick="del_kpyrule_Tr(this)"/>'
		code = code + '</td>';
		code = code + '</tr>';
	}
	return code;
}

function setkpyClientIP(ip, mac, name) {
	E("merlinclash_koolproxy_acl_ip").value = ip;
	E("merlinclash_koolproxy_acl_name").value = name;
	E("merlinclash_koolproxy_acl_mac").value = mac;
	hidekpyClients_Block();
}

function pullKPYLANIPList(obj){
	var element = E('KPYClientList_Block');
	var isMenuopen = element.offsetWidth > 0 || element.offsetHeight > 0;
	if(isMenuopen == 0){
		obj.src = "/images/arrow-top.gif"
		element.style.display = 'block';
	}
	else
		hidekpyClients_Block();
}

function hidekpyClients_Block(){
	E("pull_arrow").src = "/images/arrow-down.gif";
	E('KPYClientList_Block').style.display='none';
	validator.validIPForm(E("merlinclash_koolproxy_acl_ip"), 0);
}
//----------------------------KoolProxy代码部分END---------------------------------//
//----------------------------网易云访问控制代码部分BEGIN-------------------------------//
function getUNMACLConfigs() {
	var dict = {};
	for (var field in db_unmacl) {
		names = field.split("_");
		dict[names[names.length - 1]] = 'ok';
	}
	unmacl_confs = {};
	var p = "merlinclash_unblockmusic_acl";
	var params = ["ip", "name", "mode"];
	for (var field in dict) {
		var obj = {};
		if (typeof db_unmacl[p + "_mac_" + field] == "undefined") {
			obj["mac"] = '';
		} else {
			obj["mac"] = db_unmacl[p + "_mac_" + field];
		}
		for (var i = 0; i < params.length; i++) {
			var ofield = p + "_" + params[i] + "_" + field;
			if (typeof db_unmacl[ofield] == "undefined") {
				obj = null;
				break;
			}
			obj[params[i]] = db_unmacl[ofield];
		}
		if (obj != null) {
			var node_a = parseInt(field);
			if (node_a > unmacl_node_max) {
				unmacl_node_max = node_a;
			}
			obj["unmacl_node"] = field;
			unmacl_confs[field] = obj;
		}
	}
	return unmacl_confs;
}

function addUNMTr() {
	if(!$.trim($('#merlinclash_unblockmusic_acl_ip').val()) && !$.trim($('#merlinclash_unblockmusic_acl_mac').val())){
		alert("主机IP地址/主机MAC地址不能同时为空！");
		return false;
	}
	if(!$.trim($('#merlinclash_unblockmusic_acl_name').val())){
		alert("主机别名不能为空！");
		return false;
	}
	var unmacls = {};
	var p = "merlinclash_unblockmusic_acl";
	unmacl_node_max += 1;
	var params = ["ip", "name", "mac", "mode"];
	for (var i = 0; i < params.length; i++) {
		unmacls[p + "_" + params[i] + "_" + unmacl_node_max] = $('#' + p + "_" + params[i]).val();
		if($('#' + p + "_" + params[i]).val() == ""){
			unmacls[p + "_" + params[i] + "_" + unmacl_node_max] = " ";
		}
	}

	var id = parseInt(Math.random() * 100000000);
	var postData = {"id": id, "method": "dummy_script.sh", "params":[2], "fields": unmacls};
	$.ajax({
		type: "POST",
		cache:false,
		url: "/_api/",
		data: JSON.stringify(postData),
		dataType: "json",
		success: function(response) {
			if (response.result == id){
				refresh_unmacl_table();
				E("merlinclash_unblockmusic_acl_name").value = "";
				E("merlinclash_unblockmusic_acl_ip").value = "";
				E("merlinclash_unblockmusic_acl_mac").value = "";
				E("merlinclash_unblockmusic_acl_mode").value = "1";
			}
		}
	});
	unmaclid = 0;
}

function delUNMTr(o) {
	var id = $(o).attr("id");
	var ids = id.split("_");
	var p = "merlinclash_unblockmusic_acl";
	id = ids[ids.length - 1];
	var unmacls = {};
	var params = ["ip", "name", "mac", "mode"];
	for (var i = 0; i < params.length; i++) {
		db_merlinclash[p + "_" + params[i] + "_" + id] = unmacls[p + "_" + params[i] + "_" + id] = "";
	}
	var id = parseInt(Math.random() * 100000000);
	var postData = {"id": id, "method": "dummy_script.sh", "params":[2], "fields": unmacls};
	$.ajax({
		type: "POST",
		cache:false,
		url: "/_api/",
		data: JSON.stringify(postData),
		dataType: "json",
		success: function(response) {
			refresh_unmacl_table();
		}
	});
}

function refresh_unmacl_table(q) {
	$.ajax({
		type: "GET",
		url: "/_api/merlinclash_unblockmusic_acl",
		dataType: "json",
		async:false,
		success: function(data){
			db_unmacl=data.result[0];
			refresh_unmacl_html();
			for (var i = 1; i < unmacl_node_max + 1; i++) {
				$('#merlinclash_unblockmusic_acl_mode_' + i).val(db_unmacl["merlinclash_unblockmusic_acl_mode_" + i]);
				$('#merlinclash_unblockmusic_acl_name_' + i).val(db_unmacl["merlinclash_unblockmusic_acl_name_" + i]);
			}
			if (typeof db_unmacl["merlinclash_unblockmusic_acl_default"] !== "undefined"){
				$('#merlinclash_unblockmusic_acl_default').val(db_unmacl["merlinclash_unblockmusic_acl_default"]);
			}else{
				$('#merlinclash_unblockmusic_acl_default').val("1");
			}

	  	}
	});
}

function refresh_unmacl_html() {
	unmacl_confs = getUNMACLConfigs();
	var n = 0;
	for (var i in unmacl_confs) {
		n++;
	}
	var code = '';
	code += '<table width="750px" border="0" align="center" cellpadding="4" cellspacing="0" class="FormTable_table unmacl_lists" style="margin:-1px 0px 0px 0px;">'
	code += '<tr>'
	code += '<th width="180px" style="text-align: center; vertical-align: middle;">主机IP地址</th>'
	code += '<th width="160px" style="text-align: center; vertical-align: middle;">mac地址</th>'
	code += '<th width="160px" style="text-align: center; vertical-align: middle;">主机别名</th>'
	code += '<th width="160px" style="text-align: center; vertical-align: middle;">访问控制</th>'
	code += '<th width="70px" style="text-align: center; vertical-align: middle;">添加/删除</th>'
	code += '</tr>'
	code += '</table>'										
	// acl table input area
	code += '<table id="UNMACL_table" width="750px" border="0" align="center" cellpadding="4" cellspacing="0" class="list_table unmacl_lists" style="margin:-1px 0px 0px 0px;">'
		code += '<tr>'
	//主机ip
			code += '<td width="180px">'
			code += '<input type="text" maxlength="50" class="input_15_table" id="merlinclash_unblockmusic_acl_ip" align="left" onkeypress="return validator.isIPAddr(this, event)" style="float:center;width:145px;text-align:center" autocomplete="off" onClick="hideUNMClients_Block();" autocorrect="off" autocapitalize="off">'
			code += '<img id="pull_arrow" height="14px;" src="images/arrow-down.gif" style="float:right;" align="right" onclick="pullUNMLANIPList(this);" title="<#select_IP#>">'
			code += '<div id="UNMClientList_Block" class="clientlist_dropdown" style="margin-left:2px;width:235px;"></div>'
			code += '</td>'
	//主机mac
			code += '<td width="160px">'
			code += '<input type="text" id="merlinclash_unblockmusic_acl_mac" name="merlinclash_unblockmusic_acl_mac" class="input_15_table" maxlength="50" style="width:140px;text-align:center" placeholder="" />'
			code += '</td>'
	//主机别名
			code += '<td width="160px">'
			code += '<input type="text" id="merlinclash_unblockmusic_acl_name" name="merlinclash_unblockmusic_acl_name" class="input_15_table" maxlength="50" style="width:140px;text-align:center" placeholder="" />'
			code += '</td>'
	//访问控制
			code += '<td width="160px">'
			code += '<select id="merlinclash_unblockmusic_acl_mode" name="merlinclash_unblockmusic_acl_mode" style="width:140px;margin:-1px 0px 0px 2px;text-align:middle;padding-left: 0px;" class="input_option">'
			code +=	'<option value="1">解锁</option>'
			code +=	'<option value="0">不解锁</option>'																																					
			code +=	'</select>'
			code += '</td>'
	// add/delete 按钮
			code += '<td width="66px">'
			code += '<input style="margin-left: 6px;margin: -3px 0px -5px 6px;" type="button" class="add_btn" onclick="addUNMTr()" value="" />'
			code += '</td>'
		code += '</tr>'														
	for (var field in unmacl_confs) {
		var unmc = unmacl_confs[field];
		code += '<tr id="unmacl_tr_' + unmc["unmacl_node"] + '">';
		code = code + '<td>';
		code = code + '<input type="text" placeholder="" id="merlinclash_unblockmusic_acl_ip_' + unmc["unmacl_node"] + '" name="merlinclash_unblockmusic_acl_ip_' + unmc["unmacl_node"] + '" class="input_15_table" maxlength="50" style="width:140px; text-align:center"" value="' + unmc["ip"] + '" />';
		code = code + '</td>';
		code = code + '<td>';
		code = code + '<input type="text" placeholder="" id="merlinclash_unblockmusic_acl_mac_' + unmc["unmacl_node"] + '" name="merlinclash_unblockmusic_acl_mac_' + unmc["unmacl_node"] + '" class="input_15_table" maxlength="50" style="width:140px; text-align:center"" value="' + unmc["mac"] + '" />';
		code = code + '</td>';
		code = code + '<td>';
		code = code + '<input type="text" placeholder="" id="merlinclash_unblockmusic_acl_name_' + unmc["unmacl_node"] + '" name="merlinclash_unblockmusic_acl_name_' + unmc["unmacl_node"] + '" class="input_15_table" maxlength="50" style="width:140px; text-align:center"" value="' + unmc["name"] + '" />';
		code = code + '</td>';
		code = code + '<td>';
		code = code + '<select id="merlinclash_unblockmusic_acl_mode_' + unmc["unmacl_node"] + '" name="merlinclash_unblockmusic_acl_mode_' + unmc["unmacl_node"] + '" style="width:140px;margin:-1px 0px 0px 2px;" class="input_option">';
		code = code + '<option value="1">解锁</option>';
		code = code + '<option value="0">不解锁</option>';
		code = code + '</select>'
		code = code + '</td>';
		code = code + '<td>';
		code = code + '<input style="margin: -3px 0px -5px 6px;" id="unmacl_node_' + unmc["unmacl_node"] + '" class="remove_btn" type="button" onclick="delUNMTr(this);" value="">'
		code = code + '</td>';
		code = code + '</tr>';
	}
	code = code + '<tr>';
	if (n == 0) {
		code = code + '<td style="text-align: center;">所有主机</td>';
	} else {
		code = code + '<td style="text-align: center;">其它主机</td>';
	}
	code = code + '<td style="text-align: center;">缺省规则</td>';
	code = code + '<td style="text-align: center;">缺省规则</td>';
	code = code + '<td>';
	code = code + '<select id="merlinclash_unblockmusic_acl_default" name="merlinclash_unblockmusic_acl_default" style="width:140px;margin:-1px 0px 0px 2px;" class="input_option";">';
	code = code + '<option value="0">不解锁</option>';
	code = code + '<option value="1" selected>解锁</option>';
	code = code + '</select>';
	code = code + '</td>';
	code = code + '<td>';
	code = code + '</td>';
	code = code + '</tr>';
	code += '</table>';

	$(".unmacl_lists").remove();
	$('#merlinclash_UNMACL_table').after(code);

	showDropdownClientList('setunmClientIP', 'ip>mac', 'all', 'UNMClientList_Block', 'pull_arrow', 'online');

}

function setunmClientIP(ip, mac, name) {
	E("merlinclash_unblockmusic_acl_ip").value = ip;
	E("merlinclash_unblockmusic_acl_name").value = name;
	E("merlinclash_unblockmusic_acl_mac").value = mac;
	hideUNMClients_Block();
}

function pullUNMLANIPList(obj){
	var element = E('UNMClientList_Block');
	var isMenuopen = element.offsetWidth > 0 || element.offsetHeight > 0;
	if(isMenuopen == 0){
		obj.src = "/images/arrow-top.gif"
		element.style.display = 'block';
	}
	else
		hideUNMClients_Block();
}

function hideUNMClients_Block(){
	E("pull_arrow").src = "/images/arrow-down.gif";
	E('UNMClientList_Block').style.display='none';
	validator.validIPForm(E("merlinclash_unblockmusic_acl_ip"), 0);
}
//----------------------------网易云访问控制代码部分END---------------------------------//
//----------------------------自定规则代码部分BEGIN--------------------------------------//
function refresh_acl_table(q) {
$.ajax({
	type: "GET",
	url: "/_api/merlinclash_acl",
	dataType: "json",
	async: false,
	success: function(data) {
		db_acl = data.result[0];
		refresh_acl_html();
			
		//write dynamic table value
		for (var i = 1; i < acl_node_max + 1; i++) {
			$('#merlinclash_acl_type_' + i).val(db_acl["merlinclash_acl_type_" + i]);
			$('#merlinclash_acl_content_' + i).val(db_acl["merlinclash_acl_content_" + i]);
			$('#merlinclash_acl_lianjie_' + i).val(db_acl["merlinclash_acl_lianjie_" + i]);
			
		}
		//after table generated and value filled, set default value for first line_image1
		$('#merlinclash_acl_type').val("SRC-IP-CIDR");
	}
});
}
function addTr() {
	if(!$.trim($('#merlinclash_acl_content').val())){
		alert("内容不能为空！");
		return false;
	}
	if(!$.trim($('#merlinclash_acl_lianjie').val())){
		alert("连接方式不能为空！");
		return false;
	}
	var acls = {};
	var p = "merlinclash_acl";
	acl_node_max += 1;
	var params = ["type", "content", "lianjie"];
	for (var i = 0; i < params.length; i++) {
		acls[p + "_" + params[i] + "_" + acl_node_max] = Base64.encode(encodeURIComponent($('#' + p + "_" + params[i]).val()));
	}
	var id = parseInt(Math.random() * 100000000);
	var postData = {"id": id, "method": "dummy_script.sh", "params":[], "fields": acls};
	$.ajax({
		type: "POST",
		cache:false,
		url: "/_api/",
		data: JSON.stringify(postData),
		dataType: "json",
		error: function(xhr) {
			console.log("error in posting config of table");
		},
		success: function(response) {
			refresh_acl_table();
			proxygroup_select_get();
			E("merlinclash_acl_content").value = ""
			E("merlinclash_acl_lianjie").value = ""
		}
	});
	aclid = 0;
}
function delTr(o) {
	var id = $(o).attr("id");
	var ids = id.split("_");
	var p = "merlinclash_acl";
	id = ids[ids.length - 1];
	var acls = {};
	var params = ["type", "content", "lianjie"];
	for (var i = 0; i < params.length; i++) {
		db_merlinclash[p + "_" + params[i] + "_" + id] = acls[p + "_" + params[i] + "_" + id] = "";
	}
	var id = parseInt(Math.random() * 100000000);
	var postData = {"id": id, "method": "dummy_script.sh", "params":[], "fields": acls};

	$.ajax({
		type: "POST",
		cache:false,
		url: "/_api/",
		data: JSON.stringify(postData),
		dataType: "json",
		success: function(response) {			
			refresh_acl_table();
			proxygroup_select_get();
		}
	});
}
//自定规则
function refresh_acl_html() {
	acl_confs = getACLConfigs();
	var n = 0;
	for (var i in acl_confs) {
		n++;
	}
	var code = '';
	// acl table th
	code += '<table width="750px" border="0" align="center" cellpadding="4" cellspacing="0" class="FormTable_table acl_lists" style="margin:-1px 0px 0px 0px;">'
	code += '<tr>'
	code += '<th width="30%" style="text-align: center; vertical-align: middle;"><a class="hintstyle" href="javascript:void(0);" onclick="openmcHint(2)">类型</a></th>'
	code += '<th width="40%" style="text-align: center; vertical-align: middle;"><a class="hintstyle" href="javascript:void(0);" onclick="openmcHint(3)">内容</a></th>'
	code += '<th width="20%" style="text-align: center; vertical-align: middle;"><a class="hintstyle" href="javascript:void(0);" onclick="openmcHint(4)">连接方式</a></th>'
	code += '<th width="10%">操作</th>'
	code += '</tr>'
	code += '</table>'
	// acl table input area
	code += '<table id="ACL_table" width="750px" border="0" align="center" cellpadding="4" cellspacing="0" class="list_table acl_lists" style="margin:-1px 0px 0px 0px;">'
		code += '<tr>'
	//类型 
			code += '<td width="30%">'
			code += '<select id="merlinclash_acl_type" style="width:140px;margin:0px 0px 0px 2px;text-align:center;text-align-last:center;padding-left: 12px;" class="input_option">'
			code += '<option value="SRC-IP-CIDR">SRC-IP-CIDR</option>'
			code += '<option value="IP-CIDR">IP-CIDR</option>'
			code += '<option value="DOMAIN-SUFFIX">DOMAIN-SUFFIX</option>'
			code += '<option value="DOMAIN">DOMAIN</option>'
			code += '<option value="DOMAIN-KEYWORD">DOMAIN-KEYWORD</option>'
			code += '<option value="DST-PORT">DST-PORT</option>'
			code += '<option value="SRC-PORT">SRC-PORT</option>'
			code += '<option value="SCRIPT">SCRIPT</option>'
			code += '</select>'
			code += '</td>'
	//内容
			code += '<td width="40%">'
			code += '<input type="text" id="merlinclash_acl_content" class="input_15_table" maxlength="50" style="width:200px;text-align:center" placeholder="" />'
			code += '</td>'
	//连接
			code += '<td width="20%">'
				code += '<select id="merlinclash_acl_lianjie" style="width:140px;margin:0px 0px 0px 2px;text-align:center;text-align-last:center;padding-left: 12px;" class="input_option">'
				code += '</select>'
			code += '</td>'	
	// add/delete 按钮
			code += '<td width="10%">'
			code += '<input style="margin-left: 6px;margin: -2px 0px -4px -2px;" type="button" class="add_btn" onclick="addTr()" value="" />'
			code += '</td>'
		code += '</tr>'
	// acl table rule area
	for (var field in acl_confs) {
		var ac = acl_confs[field];		
		code += '<tr id="acl_tr_' + ac["acl_node"] + '">';
			code += '<td width="30%" id="merlinclash_acl_type_' +ac["acl_node"] + '">' + ac["type"] + '</td>';
			code += '<td width="40%" id="merlinclash_acl_content_' +ac["acl_node"] + '">' + ac["content"] + '</td>';
			code += '<td width="20%" id="merlinclash_acl_lianjie_' +ac["acl_node"] + '">' + ac["lianjie"] + '</td>';			
			
			code += '<td width="10%">';
				code += '<input style="margin: -2px 0px -4px -2px;" id="acl_node_' + ac["acl_node"] + '" class="remove_btn" type="button" onclick="delTr(this);" value="">'
			code += '</td>';
		code += '</tr>';
	}
	code += '</table>';

	$(".acl_lists").remove();
	$('#merlinclash_acl_table').after(code);

}
function getACLConfigs() {
	var dict = {};
	for (var field in db_acl) {
		names = field.split("_");
		
		dict[names[names.length - 1]] = 'ok';
	}
	acl_confs = {};
	var p = "merlinclash_acl";
	var params = ["type", "content", "lianjie"];
	for (var field in dict) {
		var obj = {};
		for (var i = 0; i < params.length; i++) {
			var ofield = p + "_" + params[i] + "_" + field;
			if (typeof db_acl[ofield] == "undefined") {
				obj = null;
				break;
			}
			obj[params[i]] = decodeURIComponent(Base64.decode(db_acl[ofield]));
			
		}
		if (obj != null) {
			var node_a = parseInt(field);
			if (node_a > acl_node_max) {
				acl_node_max = node_a;
			}
			obj["acl_node"] = field;
			acl_confs[field] = obj;
		}
	}
	return acl_confs;
}
//----------------------------自定规则代码部分END--------------------------------------//
//----------------------------黑白郎君访问控制部分BEGIN--------------------------------//
function getnoKPACLConfigs() {
	var dict = {};
	for (var field in db_nokpacl) {
		names = field.split("_");
		dict[names[names.length - 1]] = 'ok';
	}
	nokpacl_confs = {};
	var p = "merlinclash_nokpacl";
	var params = ["ip", "mac", "port", "mode"];
	for (var field in dict) {
		var obj = {};
		if (typeof db_nokpacl[p + "_name_" + field] == "undefined") {
			obj["name"] = db_nokpacl[p + "_ip_" + field];
		} else {
			obj["name"] = db_nokpacl[p + "_name_" + field];
		}
		for (var i = 0; i < params.length; i++) {
			var ofield = p + "_" + params[i] + "_" + field;
			if (typeof db_nokpacl[ofield] == "undefined") {
				obj = null;
				break;
			}
			obj[params[i]] = db_nokpacl[ofield];
		}
		if (obj != null) {
			var node_a = parseInt(field);
			if (node_a > nokpacl_node_max) {
				nokpacl_node_max = node_a;
			}
			obj["nokpacl_node"] = field;
			nokpacl_confs[field] = obj;
		}
	}
	return nokpacl_confs;
}
function addnokpaclTr() {
	if(!$.trim($('#merlinclash_nokpacl_ip').val())){
		alert("主机IP地址不能为空！");
		return false;
	}
	if(!$.trim($('#merlinclash_nokpacl_name').val())){
		alert("主机别名不能为空！");
		return false;
	}
	var nokpacls = {};
	var p = "merlinclash_nokpacl";
	nokpacl_node_max += 1;
	var params = ["ip", "mac", "name", "port", "mode"];
	for (var i = 0; i < params.length; i++) {
		nokpacls[p + "_" + params[i] + "_" + nokpacl_node_max] = $('#' + p + "_" + params[i]).val();
	}
	var id = parseInt(Math.random() * 100000000);
	var postData = {"id": id, "method": "dummy_script.sh", "params":[], "fields": nokpacls};
	$.ajax({
		type: "POST",
		cache:false,
		url: "/_api/",
		data: JSON.stringify(postData),
		dataType: "json",
		error: function(xhr) {
			console.log("error in posting config of table");
		},
		success: function(response) {
			refresh_nokpacl_table();
			E("merlinclash_nokpacl_name").value = ""
			E("merlinclash_nokpacl_ip").value = ""
			E("merlinclash_nokpacl_mac").value = ""
		}
	});
	nokpaclid = 0;
}
function delnokpaclTr(o) {
	var id = $(o).attr("id");
	var ids = id.split("_");
	var p = "merlinclash_nokpacl";
	id = ids[ids.length - 1];
	var nokpacls = {};
	var params = ["ip", "mac", "name", "port", "mode"];
	for (var i = 0; i < params.length; i++) {
		db_merlinclash[p + "_" + params[i] + "_" + id] = nokpacls[p + "_" + params[i] + "_" + id] = "";
	}
	var id = parseInt(Math.random() * 100000000);
	var postData = {"id": id, "method": "dummy_script.sh", "params":[], "fields": nokpacls};
	$.ajax({
		type: "POST",
		cache:false,
		url: "/_api/",
		data: JSON.stringify(postData),
		dataType: "json",
		success: function(response) {
			refresh_nokpacl_table();
		}
	});
}
function refresh_nokpacl_table(q) {
	$.ajax({
		type: "GET",
		url: "/_api/merlinclash_nokpacl",
		dataType: "json",
		async: false,
		success: function(data) {
			db_nokpacl = data.result[0];
			refresh_nokpacl_html();
			//write default rule port
			//console.log(db_nokpacl["merlinclash_nokpacl_default_port"]);
			if (typeof db_nokpacl["merlinclash_nokpacl_default_port"] != "undefined") {
				$('#merlinclash_nokpacl_default_port').val(db_nokpacl["merlinclash_nokpacl_default_port"]);
			} else {
				//console.log("进来这里");
				$('#merlinclash_nokpacl_default_port').val("all");
			}
			//write dynamic table value
			for (var i = 1; i < nokpacl_node_max + 1; i++) {
				$('#merlinclash_nokpacl_mode_' + i).val(db_nokpacl["merlinclash_nokpacl_mode_" + i]);
				$('#merlinclash_nokpacl_port_' + i).val(db_nokpacl["merlinclash_nokpacl_port_" + i]);
				$('#merlinclash_nokpacl_name_' + i).val(db_nokpacl["merlinclash_nokpacl_name_" + i]);
				$('#merlinclash_nokpacl_mac_' + i).val(db_nokpacl["merlinclash_nokpacl_mac_" + i]);
			}
			if(db_merlinclash["merlinclash_nokpacl_default_mode"]){
				$('#merlinclash_nokpacl_default_mode').val(db_merlinclash["merlinclash_nokpacl_default_mode"]);
			}
			//set default rule port to all when game mode enabled
			set_nodefault_port();
			//after table generated and value filled, set default value for first line_image1
			$('#merlinclash_nokpacl_mode').val("0");
			$('#merlinclash_nokpacl_port').val("all");
		}
	});
}
function set_nomode_1() {
	//set the first line of the table, if mode is gfwlist mode or game mode,set the port to all
	if ($('#merlinclash_nokpacl_mode').val() == 0) {
		$("#merlinclash_nokpacl_port").val("all");
		E("merlinclash_nokpacl_port").readOnly = "readonly";
		E("merlinclash_nokpacl_port").title = "不可更改，不走代理下默认全端口";
	} else if ($('#merlinclash_nokpacl_mode').val() == 1) {
		//console.log($('#merlinclash_nokpacl_mode').val());
		$("#merlinclash_nokpacl_port").val("80,443");
		E("merlinclash_nokpacl_port").readOnly = "";
		E("merlinclash_nokpacl_port").title = "";
	}
}
function set_nomode_2(o) {
	var id2 = $(o).attr("id");
	var ids2 = id2.split("_");
	id2 = ids2[ids2.length - 1];
	if ($(o).val() == 0) {
		$("#merlinclash_nokpacl_port_" + id2).val("all");
		E("merlinclash_nokpacl_port_" + id2).readOnly = "readonly";
	} else if ($(o).val() == 1) {
		$("#merlinclash_nokpacl_port_" + id2).val("all");
		E("merlinclash_nokpacl_port_" + id2).readOnly = "";
	} else if ($(o).val() == 2) {
		$("#merlinclash_nokpacl_port_" + id2).val("22,80,443");
	}
}
function set_nodefault_port() {
	//console.log($('#merlinclash_nokpacl_default_mode').val());
	if ($('#merlinclash_nokpacl_default_mode').val() == 0) {	
		$("#merlinclash_nokpacl_default_port").val("all");
		E("merlinclash_nokpacl_default_port").readOnly = "readonly";
		E("merlinclash_nokpacl_default_port").title = "不可更改，不走代理下默认全端口";
	} else {
		
		//$("#merlinclash_nokpacl_default_port").val("all");
		//console.log(db_merlinclash["merlinclash_nokpacl_default_port"]);
		if(db_merlinclash["merlinclash_nokpacl_default_port"]){
			$("#merlinclash_nokpacl_default_port").val(db_merlinclash["merlinclash_nokpacl_default_port"]);
		}else{
			$("#merlinclash_nokpacl_default_port").val("all");
		}
		
		E("merlinclash_nokpacl_default_port").readOnly = "";
		E("merlinclash_nokpacl_default_port").title = "";
	}
}
function refresh_nokpacl_html() {
	nokpacl_confs = getnoKPACLConfigs();
	var n = 0;
	for (var i in nokpacl_confs) {
		n++;
	}
	var code = '';
	// acl table th
	code += '<table width="750px" border="0" align="center" cellpadding="4" cellspacing="0" class="FormTable_table nokpacl_lists" style="margin:-1px 0px 0px 0px;">'
	code += '<tr>'
	code += '<th width="23%">主机IP地址</th>'
	code += '<th width="23%" style="display: none">主机MAC地址</th>'
	code += '<th width="23%">主机别名</th>'
	code += '<th width="23%">访问控制</th>'
	code += '<th width="23%">目标端口</th>'
	code += '<th width="8%">操作</th>'
	code += '</tr>'
	code += '</table>'
	// acl table input area
	code += '<table id="noKPACL_table" width="750px" border="0" align="center" cellpadding="4" cellspacing="0" class="list_table nokpacl_lists" style="margin:-1px 0px 0px 0px;">'
	code += '<tr>'
	// ip addr merlinclash_nokpacl_ip 主机IP地址
	code += '<td width="23%">'
	code += '<input type="text" maxlength="15" class="input_15_table" id="merlinclash_nokpacl_ip" align="left" style="float:left;width:110px;margin-left:16px;text-align:center" autocomplete="off" onClick="hidenokpClients_Block();" autocorrect="off" autocapitalize="off">'
	code += '<img id="pull_arrow" height="14px;" src="images/arrow-down.gif" align="right" onclick="pullnokpLANIPList(this);" title="<#select_IP#>">'
	code += '<div id="nokpClientList_Block" class="clientlist_dropdown" style="margin-left:2px;margin-top:25px;"></div>'
	code += '</td>'
	// name merlinclash_nokpacl_mac 主机MAC地址
	code += '<td width="23%" style="display: none;">'
	code += '<input type="text" id="merlinclash_nokpacl_mac" class="input_15_table" maxlength="50" style="width:140px;text-align:center" placeholder="" />'
	code += '</td>'
	// name merlinclash_kpacl_name 主机别名
	code += '<td width="23%">'
	code += '<input type="text" id="merlinclash_nokpacl_name" class="input_15_table" maxlength="50" style="width:140px;text-align:center" placeholder="" />'
	code += '</td>'
	// mode merlinclash_kpacl_mode 访问控制
	code += '<td width="23%">'
	code += '<select id="merlinclash_nokpacl_mode" style="width:140px;margin:0px 0px 0px 2px;text-align:center;text-align-last:center;padding-left: 12px;" class="input_option" onchange="set_nomode_1(this);">'
	code += '<option value="0">不通过代理</option>'
	code += '<option value="1">通过clash</option>'
	code += '</select>'
	code += '</td>'
	// port merlinclash_kpacl_port 目标端口
	code += '<td width="23%">'
	code += '<select id="merlinclash_nokpacl_port" style="width:152px;margin:0px 0px 0px 2px;text-align-last:center;padding-left: 12px;" class="input_option">'
	code += '<option value="all">all</option>'
	code += '<option value="80,443">80,443</option>'
	code += '<option value="22,80,443">22,80,443</option>'
	code += '</select>'
	code += '</td>'
	// add/delete 按钮
	code += '<td width="8%">'
	code += '<input style="margin-left: 6px;margin: -2px 0px -4px -2px;" type="button" class="add_btn" onclick="addnokpaclTr()" value="" />'
	code += '</td>'
	code += '</tr>'
	// acl table rule area
	for (var field in nokpacl_confs) {
		var nokp = nokpacl_confs[field];
		code += '<tr id="nokpacl_tr_' + nokp["nokpacl_node"] + '">';
		// ip merlinclash_nokpacl_ip 主机IP地址
		code += '<td width="23%">' + nokp["ip"] + '</td>';
		//merlinclash_nokpacl_mac 主机MAC地址

		//merlinclash_nokpacl_name 主机别名
		code += '<td width="23%">';
		code += '<input type="text" placeholder="' + nokp["nokpacl_node"] + '号机" id="merlinclash_nokpacl_name_' + nokp["nokpacl_node"] + '" name="merlinclash_nokpacl_name_' + nokp["nokpacl_node"] + '" class="input_option_2" maxlength="50" style="width:140px;" placeholder="" />';
		code += '<br>';
		code += '<input type="text" placeholder="' + nokp["nokpacl_node"] + '号机" id="merlinclash_nokpacl_mac_' + nokp["nokpacl_node"] + '" name="merlinclash_nokpacl_mac_' + nokp["nokpacl_node"] + '" class="input_option_2" maxlength="50" style="width:140px;" placeholder="" />';
		code += '</td>';
		//merlinclash_nokpacl_mode 访问控制
		code += '<td width="23%">';
		code += '<select id="merlinclash_nokpacl_mode_' + nokp["nokpacl_node"] + '" name="merlinclash_nokpacl_mode_' + nokp["nokpacl_node"] + '" style="width:140px;margin:0px 0px 0px 2px;" class="sel_option" onchange="set_nomode_2(this);">';
			code += '<option value="0">不通过代理</option>';
			code += '<option value="1">通过clash</option>';
		code += '</select>'
		code += '</td>';
		//merlinclash_nokpacl_port 目标端口
		code += '<td width="23%">';
		if (nokp["mode"] == 0) {
			code += '<input type="text" id="merlinclash_nokpacl_port_' + nokp["nokpacl_node"] + '" name="merlinclash_nokpacl_port_' + nokp["nokpacl_node"] + '" class="input_option_2" maxlength="50" style="width:140px;" title="不可更改，不通过clash下默认全端口" readonly = "readonly" />';
		} else {
			code += '<input type="text" id="merlinclash_nokpacl_port_' + nokp["nokpacl_node"] + '" name="merlinclash_nokpacl_port_' + nokp["nokpacl_node"] + '" class="input_option_2" maxlength="50" style="width:140px;" placeholder="" />';
		}
		code += '</td>';
		//按钮
		code += '<td width="8%">';
		code += '<input style="margin: -2px 0px -4px -2px;" id="nokpacl_node_' + nokp["nokpacl_node"] + '" class="remove_btn" type="button" onclick="delnokpaclTr(this);" value="">'
		code += '</td>';
		code += '</tr>';
	}
	//底行
	code += '<tr>';
	//所有主机
	if (n == 0) {
		code += '<td width="23%">所有主机</td>';
	} else {
		code += '<td width="23%">其它主机</td>';
	}
	//默认规则
	code += '<td width="23%">默认规则</td>';
	//访问控制
	
		code += '<td width="23%">';
		code += '<select id="merlinclash_nokpacl_default_mode" style="width:140px;margin:0px 0px 0px 2px;" class="sel_option" onchange="set_nodefault_port();">';
			code += '<option value="0">不通过代理</option>';
			code += '<option value="1" selected>通过clash</option>';
		code += '</select>';
		code += '</td>';
	
	//默认端口
	code += '<td width="23%">';
	code += '<input type="text" id="merlinclash_nokpacl_default_port" class="input_option_2" maxlength="50" style="width:140px;" placeholder="" />';
	code += '</td>';
	//按钮为空
	code += '<td width="8%">';
	code += '</td>';
	code += '</tr>';
	code += '</table>';

	$(".nokpacl_lists").remove();
	$('#merlinclash_nokpacl_table').after(code);
	
	showDropdownClientList('setnokpClientIP', 'ip>mac>name', 'all', 'nokpClientList_Block', 'pull_arrow', 'online');
}
function setnokpClientIP(ip, mac, name) {
	E("merlinclash_nokpacl_ip").value = ip;
	E("merlinclash_nokpacl_mac").value = mac;
	E("merlinclash_nokpacl_name").value = name;
	hidenokpClients_Block();
}
function pullnokpLANIPList(obj) {
	var element = E('nokpClientList_Block');
	var isMenuopen = element.offsetWidth > 0 || element.offsetHeight > 0;
	if (isMenuopen == 0) {
		obj.src = "/images/arrow-top.gif"
		element.style.display = 'block';
	} else{
		hidenokpClients_Block();
	}
}
function hidenokpClients_Block() {
	E("pull_arrow").src = "/images/arrow-down.gif";
	E('nokpClientList_Block').style.display = 'none';
}
//----------------------------访问控制部分END----------------------------------//
//----------------------------KCP代码部分BEGIN--------------------------------------//
function refresh_kcp_table(q) {
	$.ajax({
		type: "GET",
		url: "/_api/merlinclash_kcp",
		dataType: "json",
		async: false,
		success: function(data) {
			db_kcp = data.result[0];
			refresh_kcp_html();
				
			//write dynamic table value
			for (var i = 1; i < kcp_node_max + 1; i++) {
				$('#merlinclash_kcp_lport_' + i).val(db_kcp["merlinclash_kcp_lport_" + i]);
				$('#merlinclash_kcp_server_' + i).val(db_kcp["merlinclash_kcp_server_" + i]);
				$('#merlinclash_kcp_port_' + i).val(db_kcp["merlinclash_kcp_port_" + i]);
				$('#merlinclash_kcp_param_' + i).val(db_kcp["merlinclash_kcp_param_" + i]);
			}
			//after table generated and value filled, set default value for first line_image1
		}
	});
}
function addTrkcp() {
	var kcps = {};
	var p = "merlinclash_kcp";
	kcp_node_max += 1;
	var params = ["lport", "server", "port", "param"];
	for (var i = 0; i < params.length; i++) {
		kcps[p + "_" + params[i] + "_" + kcp_node_max] = $('#' + p + "_" + params[i]).val();
		
	}
	var id = parseInt(Math.random() * 100000000);
	var postData = {"id": id, "method": "dummy_script.sh", "params":[], "fields": kcps};
	$.ajax({
		type: "POST",
		cache:false,
		url: "/_api/",
		data: JSON.stringify(postData),
		dataType: "json",
		error: function(xhr) {
			console.log("error in posting config of table");
		},
		success: function(response) {
			refresh_kcp_table();
			E("merlinclash_kcp_lport").value = ""
			E("merlinclash_kcp_server").value = ""
			E("merlinclash_kcp_port").value = ""
			E("merlinclash_kcp_param").value = ""
		}
	});
	kcpid = 0;
}
function saveTrkcp(o) {
	var id = $(o).attr("id"); //kcp_nodes_1
	var ids = id.split("_");
	var p = "merlinclash_kcp";
	id = ids[ids.length - 1];
	var kcps = {};
	var params = ["lport", "server", "port", "param"];


	for (var i = 0; i < params.length; i++) {
		$("#kcp_tr_" + id + " input[name='"+ p +"_" + params[i] + "_" + id+ "']").each(function () {
			kcps[p + "_" + params[i] + "_" + id] = this.value;
		});
	}
	var id = parseInt(Math.random() * 100000000);
	var postData = {"id": id, "method": "dummy_script.sh", "params":[], "fields": kcps};

	$.ajax({
		type: "POST",
		cache:false,
		url: "/_api/",
		data: JSON.stringify(postData),
		dataType: "json",
		success: function(response) {		
			refresh_kcp_table();
			refreshpage();
		}
	});	
}
function delTrkcp(o) {
	var id = $(o).attr("id");
	var ids = id.split("_");
	var p = "merlinclash_kcp";
	id = ids[ids.length - 1];
	var kcps = {};
	var params = ["lport", "server", "port", "param"];
	for (var i = 0; i < params.length; i++) {
		db_merlinclash[p + "_" + params[i] + "_" + id] = kcps[p + "_" + params[i] + "_" + id] = "";
	}
	var id = parseInt(Math.random() * 100000000);
	var postData = {"id": id, "method": "dummy_script.sh", "params":[], "fields": kcps};

	$.ajax({
		type: "POST",
		cache:false,
		url: "/_api/",
		data: JSON.stringify(postData),
		dataType: "json",
		success: function(response) {		           
			refresh_kcp_table();
			refreshpage();
		}
	});
}
function refresh_kcp_html() {
	kcp_confs = getkcpConfigs();
	var n = 0;
	for (var i in kcp_confs) {
		n++;
	}
	var code2 = '';
	// kcp table th
	code2 += '<table width="750px" border="0" align="center" cellpadding="4" cellspacing="0" class="FormTable_table kcp_lists" style="margin:-1px 0px 0px 0px;">'
		code2 += '<tr>'
			code2 += '<th width="10%" style="text-align: center; vertical-align: middle;">监听端口</th>'
			code2 += '<th width="20%" style="text-align: center; vertical-align: middle;">kcp服务器</th>'
			code2 += '<th width="10%" style="text-align: center; vertical-align: middle;">kcp端口</th>'
			code2 += '<th width="40%" style="text-align: center; vertical-align: middle;">kcp参数</th>'
			code2 += '<th width="20%">操作</th>'
		code2 += '</tr>'
	code2 += '</table>'
	// kcp table input area
	code2 += '<table id="KCP_table" width="750px" border="0" align="center" cellpadding="4" cellspacing="0" class="list_table kcp_lists" style="margin:-1px 0px 0px 0px;">'
		code2 += '<tr>'
	//监听端口
			code2 += '<td width="10%">'
				code2 += '<input type="text" id="merlinclash_kcp_lport" class="input_15_table" maxlength="6" style="width:80%;text-align:center;" placeholder="" />'
			code2 += '</td>'
	//KCP服务器 
			code2 += '<td width="20%">'
				code2 += '<input type="text" id="merlinclash_kcp_server" class="input_15_table" maxlength="20" style="width:90%;text-align:center;" placeholder="" />'
			code2 += '</td>'
	//端口
			code2 += '<td width="10%">'
				code2 += '<input type="text" id="merlinclash_kcp_port" class="input_15_table" maxlength="6" style="width:80%;text-align:center;" placeholder="" />'
			code2 += '</td>'
	//参数
			code2 += '<td width="40%">'
				code2 += '<input type="text" id="merlinclash_kcp_param" class="input_15_table" maxlength="5000" style="width:90%;text-align:center;" placeholder="" />'
				code2 += '</td>'	
	// add/delete 按钮
			code2 += '<td width="20%">'
				code2 += '<input style="margin-left: 6px;margin: -2px 0px -4px -2px;" type="button" class="add_btn" onclick="addTrkcp()" value="" />'
			code2 += '</td>'
		code2 += '</tr>'
	// kcp table data area
	for (var field in kcp_confs) {
		var kc = kcp_confs[field];		
		code2 += '<tr id="kcp_tr_' + kc["kcp_node"] + '">';
			code2 += '<td width="10%">'
				code2 += '<input type="text" id="merlinclash_kcp_lport_' + kc["kcp_node"] +' "name="merlinclash_kcp_lport_' + kc["kcp_node"] +'" class="input_option_2" maxlength="6" style="width:80%;text-align:center;" value="' + kc["lport"] +'" />'
			code2 += '</td>';
			code2 += '<td width="20%">'
				code2 += '<input type="text" id="merlinclash_kcp_server_' + kc["kcp_node"] +' "name="merlinclash_kcp_server_' + kc["kcp_node"] +'" class="input_option_2" maxlength="20" style="width:90%;text-align:center;" value="' + kc["server"] +'" />'
			code2 += '</td>';
			code2 += '<td width="10%">'
				code2 += '<input type="text" id="merlinclash_kcp_port_' + kc["kcp_node"] +' "name="merlinclash_kcp_port_' + kc["kcp_node"] +'" class="input_option_2" maxlength="6" style="width:80%;text-align:center;" value="' + kc["port"] +'" />'
			code2 += '</td>';
			code2 += '<td width="40%">'
				code2 += '<input type="text" id="merlinclash_kcp_param_' + kc["kcp_node"] +' "name="merlinclash_kcp_param_' + kc["kcp_node"] +'" class="input_option_2" maxlength="5000" style="width:90%;text-align:center;" value="' + kc["param"] +'" />'
				code2 += '</td>';
			code2 += '<td width="20%">';
				code2 += '<input style="margin: 0px 0px -4px -2px;" id="kcp_nodes_' + kc["kcp_node"] + '" class="edit_btn" type="button" onclick="saveTrkcp(this);" value="">'
				code2 += ' '
				code2 += '<input style="margin: 0px 0px -4px -2px;" id="kcp_noded_' + kc["kcp_node"] + '" class="remove_btn" type="button" onclick="delTrkcp(this);" value="">'
				//code2 += '<input style="width:60px" id="kcp_nodes_' + kc["kcp_node"] + '" class="ss_btn" type="button" onclick="saveTrkcp(this);" value="保存">'
				//code2 += ' '
				//code2 += '<input style="width:60px" id="kcp_noded_' + kc["kcp_node"] + '" class="ss_btn" type="button" onclick="delTrkcp(this);" value="删除">'
			code2 += '</td>';
		code2 += '</tr>';
	}
	code2 += '</table>';

	$(".kcp_lists").remove();
	$('#merlinclash_kcp_table').after(code2);

}
function getkcpConfigs() {
	var dictkcp = {};
	for (var field in db_kcp) {
		kcpnames = field.split("_");
		
		dictkcp[kcpnames[kcpnames.length - 1]] = 'ok';
	}
	kcp_confs = {};
	var p = "merlinclash_kcp";
	var params = ["lport", "server", "port", "param"];
	for (var field in dictkcp) {
		var obj = {};
		for (var i = 0; i < params.length; i++) {
			var ofield = p + "_" + params[i] + "_" + field;
			if (typeof db_kcp[ofield] == "undefined") {
				obj = null;
				break;
			}
			obj[params[i]] = db_kcp[ofield];
			
		}
		if (obj != null) {
			var node_a = parseInt(field);
			if (node_a > kcp_node_max) {
				kcp_node_max = node_a;
			}
			obj["kcp_node"] = field;
			kcp_confs[field] = obj;
		}
	}
	return kcp_confs;
}
//----------------------------KCP代码部分END--------------------------------------//
//-----------------------删除所有自定规则 开始----------------------//
function delallaclconfigs() {
	require(['/res/layer/layer.js'], function(layer) {
	layer.confirm('<li>确定删除所有自定义规则吗？</li>', {
		shade: 0.8,
	}, function(index) {
		getaclconfigsmax();
		if(acl_node_max != "undefined"){
			var p = "merlinclash_acl";
			acl_node_del = acl_node_max;
			var acls = {};
			var params = ["type", "content", "lianjie"];
			for (var j=acl_node_del; j>0; j--) {
				for (var i = 0; i < params.length; i++) {
					db_merlinclash[p + "_" + params[i] + "_" + j] = acls[p + "_" + params[i] + "_" + j] = "";		
				}
			}
			acl_node_max = 0;
			var id = parseInt(Math.random() * 100000000);
			var postData = {"id": id, "method": "dummy_script.sh", "params":[], "fields": acls};

			$.ajax({
				type: "POST",
				cache:false,
				url: "/_api/",
				data: JSON.stringify(postData),
				dataType: "json",
				success: function(response) {		           
					refresh_acl_table();
					refreshpage();
				}
			});	
		}
		layer.close(index);
		return true;			
	}, function(index) {
		layer.close(index);
		return false;
		});
	});		
}
function getaclconfigsmax(){
	$.ajax({
		type: "GET",
		url: "/_api/merlinclash_acl",
		dataType: "json",
		async: false,
		success: function(data) {
			db_acls = data.result[0];
			getACLConfigs();
			//after table generated and value filled, set default value for first line_image1
		}
	});
}
//-----------------------删除所有自定规则 结束----------------------//
</script>
<script>
	// IP 检查
	var IP = {
		get: (url, type) =>
			fetch(url, { method: 'GET' }).then((resp) => {
				if (type === 'text')
					return Promise.all([resp.ok, resp.status, resp.text(), resp.headers]);
				else {
					return Promise.all([resp.ok, resp.status, resp.json(), resp.headers]);
				}
			}).then(([ok, status, data, headers]) => {
				if (ok) {
					let json = {
						ok,
						status,
						data,
						headers
					}
					return json;
				} else {
					throw new Error(JSON.stringify(json.error));
				}
			}).catch(error => {
				throw error;
			}),
		parseIPIpip: (ip, elID) => {
			IP.get(`https://api.skk.moe/network/parseIp/ipip/v3/${ip}`, 'json')
				.then(resp => {
					let x = '';
					for (let i of resp.data) {
						x += (i !== '') ? `${i} ` : '';
					}
					E(elID).innerHTML = x;
				})
		},
		getIpipnetIP: () => {
			IP.get(`https://myip.ipip.net?${+(new Date)}`, 'text')
				.then(resp => E('ip-ipipnet').innerHTML = resp.data.replace('当前 IP：', '').replace('来自于：', ''));
		},
		getSohuIP: (data) => {
			E('ip-sohu').innerHTML = returnCitySN.cip;
			IP.parseIPIpip(returnCitySN.cip, 'ip-sohu-ipip');
		},
		getIpsbIP: (data) => {
			E('ip-ipsb').innerHTML = data.address;
			E('ip-ipsb-geo').innerHTML = `${data.country} ${data.province} ${data.city} ${data.isp.name}`
		},
		getIpApiIP: () => {
			IP.get(`https://api.ipify.org/?format=json&id=${+(new Date)}`, 'json')
				.then(resp => {
					E('ip-ipapi').innerHTML = resp.data.ip;
					return resp.data.ip;
				})
				.then(ip => {
					IP.parseIPIpip(ip, 'ip-ipapi-geo');
				})
		},
	};
	// 网站访问检查
	var HTTP = {
		checker: (domain, cbElID) => {
			let img = new Image;
			let timeout = setTimeout(() => {
				img.onerror = img.onload = null;
				img = null;
				E(cbElID).innerHTML = '<a class="hintstyle" href="javascript:void(0);" onclick="openmcHint(26)"><span style="color:#F00">连接超时</span></a>'
			}, 5000);
	
			img.onerror = () => {
				clearTimeout(timeout);
				E(cbElID).innerHTML = '<a class="hintstyle" href="javascript:void(0);" onclick="openmcHint(26)"><span style="color:#F00">无法访问</span></a>'
			}
	
			img.onload = () => {
				clearTimeout(timeout);
				E(cbElID).innerHTML = '<span style="color:#6C0">连接正常</span>'
			}
	
			img.src = `https://${domain}/favicon.ico?${+(new Date)}`
		},
		runcheck: () => {
			HTTP.checker('www.baidu.com', 'http-baidu');
			//HTTP.checker('s1.music.126.net/style', 'http-163');
			HTTP.checker('github.com', 'http-github');
			HTTP.checker('www.youtube.com', 'http-youtube');
		}
	};
	var merlinclash = {
		checkIP: () => {	
			IP.getIpipnetIP();
			//IP.getSohuIP();
			IP.getIpApiIP();
			HTTP.runcheck();
			setTimeout("merlinclash.checkIP();", 20000);
		},
	}
</script>
</head>
<body onload="init();">
<div id="TopBanner"></div>
<div id="Loading" class="popup_bg"></div>
<div id="LoadingBar" class="popup_bar_bg_ks" style="z-index: 200;" >
<table cellpadding="5" cellspacing="0" id="loadingBarBlock" class="loadingBarBlock" align="center">
	<tr>
		<td height="100">
		<div id="loading_block3" style="margin:10px auto;margin-left:10px;width:85%; font-size:12pt;"></div>
		<div id="loading_block2" style="margin:10px auto;width:95%;"></div>
		<div id="log_content2" style="margin-left:15px;margin-right:15px;margin-top:10px;overflow:hidden">
			<textarea cols="50" rows="30" wrap="off" readonly="readonly" id="log_content3" autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false" style="border:1px solid #000;width:99%; font-family:'Lucida Console'; font-size:11px;background:transparent;color:#FFFFFF;outline: none;padding-left:3px;padding-right:22px;overflow-x:hidden"></textarea>
		</div>
		<div id="ok_button" class="apply_gen" style="background: #000;display: none;">
			<input id="ok_button1" class="button_gen" type="button" onclick="hideMCLoadingBar()" value="确定">
		</div>
		</td>
	</tr>
</table>
</div>
<table class="content" align="center" cellpadding="0" cellspacing="0">
	<tr>
		<td width="17">&nbsp;</td>
		<td valign="top" width="202">
			<div id="mainMenu"></div>
			<div id="subMenu"></div>
		</td>
		<td valign="top">
			<div id="tabMenu" class="submenuBlock"></div>
			<table width="98%" border="0" align="left" cellpadding="0" cellspacing="0" style="display: block;">
				<tr>
					<td align="left" valign="top">
						<div>
							<table width="760px" border="0" cellpadding="5" cellspacing="0" bordercolor="#6b8fa3" class="FormTitle" id="FormTitle">
								<tr>
									<td bgcolor="#4D595D" colspan="3" valign="top">
										<div>&nbsp;</div>
										<div class="formfonttitle">Merlin Clash</div>
										<div style="float:right; width:15px; height:25px;margin-top:-20px">
											<img id="return_btn" onclick="reload_Soft_Center();" align="right" style="cursor:pointer;position:absolute;margin-left:-30px;margin-top:-25px;" title="返回软件中心" src="/images/backprev.png" onMouseOver="this.src='/images/backprevclick.png'" onMouseOut="this.src='/images/backprev.png'"></img>
										</div>
										<div style="margin:10px 0 10px 5px;" class="splitLine"></div>
										<div class="SimpleNote" id="head_illustrate"><i></i>
											<p><a href='https://github.com/Dreamacro/clash' target='_blank'><em><u>Clash</u></em></a>是一个基于规则的代理程序，支持<a href='https://github.com/shadowsocks/shadowsocks-libev' target='_blank'><em><u>SS</u></em></a>、<a href='https://github.com/shadowsocksrr/shadowsocksr-libev' target='_blank'><em><u>SSR</u></em></a>、<a href='https://github.com/v2ray/v2ray-core' target='_blank'><em><u>V2Ray</u></em></a>、<a href='https://github.com/trojan-gfw/trojan' target='_blank'><em><u>Trojan</u></em></a>等方式科学上网。</p>
											<p style="color:#FC0">注意：1.Clash需要专用订阅或配置文件才可以使用，如果您的机场没提供订阅，可以使用插件内置的2种【<a style="cursor:pointer" onclick="dingyue()" href="javascript:void(0);"><em><u>规则转换</u></em></a>】，</p>
											<p id="dingyue2" style="color:#FC0"></p>
											<p style="color:#FC0">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;2.本插件不能与【<a href="./Module_shadowsocks.asp" target="_blank"><em><u>科学上网</u></em></a>】同时运行。开启后如果Aria2/AiCloud无法外网访问，请设置<a href="./Advanced_VirtualServer_Content.asp" target="_blank"><em><u>端口转发</u></em></a>。</p>
											<p style="color:#FC0">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;3.使用延迟最低(Url-Test)&nbsp;|&nbsp;故障切换(Fallback)&nbsp;|&nbsp;负载均衡(Load-Balance)等自动策略组前，请确认您的机场允许频繁TCPing，</p>
											<p style="color:#FC0">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;否则您的帐号可能会被限制。</p>
											<p style="color:#FC0">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;4.常用clash二进制【<a href="https://github.com/flyhigherpi/merlinclash_clash_binary/tree/master/clash_binary_history" target="_blank"><em><u>文件下载</u></em></a>】。</p>
											<p id="showmsg1"></p>
											<p id="showmsg2"></p>
											<p id="showmsg3"></p>
											<p id="showmsg4"></p>
										</div>
										<!-- this is the popup area for process status -->
										<div id="detail_status"  class="content_status" style="box-shadow: 3px 3px 10px #000;margin-top: -20px;display: none;">
											<div class="user_title">【Merlin Clash】状态检测</div>
											<div style="margin-left:15px"><i>&nbsp;&nbsp;目前本功能支持Merlin Clash相关进程状态和iptables表状态检测。</i></div>
											<div style="margin: 10px 10px 10px 10px;width:98%;text-align:center;overflow:hidden">
												<textarea cols="63" rows="36" wrap="off" id="proc_status" style="width:98%;padding-left:13px;padding-right:33px;border:0px solid #222;font-family:'Lucida Console'; font-size:11px;background: transparent;color:#FFFFFF;outline: none;overflow-x:hidden;" autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"></textarea>
											</div>
											<div style="margin-top:5px;padding-bottom:10px;width:100%;text-align:center;">
												<input class="button_gen" type="button" onclick="close_proc_status();" value="返回主界面">
											</div>
										</div>
										<!-- this is the popup area for user rules -->
										<div id="vpnc_settings" class="contentMKP_qis" style="box-shadow: 3px 3px 10px #000;margin-top: -65px;display: none;">
											<div class="user_title">KidsProtect自定义规则</div>
											<div style="margin-left:15px"><i>1&nbsp;&nbsp;点击【保存文件】按钮，文本框内的内容会保存到/koolshare/koolproxy/data/user.txt。</i></div>
											<div style="margin-left:15px"><i>2&nbsp;&nbsp;如果你更改了user.txt，你需要重新重启KidsProtect插件才，新加入的规则才能生效。</i></div>
											<div style="margin-left:15px"><i>3&nbsp;&nbsp;虽然KidsProtect支持adblock规则，但是我们一点都不建议你直接使用他们的规则内容，因为这极可能导致规则冲突。</i></div>
											<div id="user_tr" style="margin: 10px 10px 10px 10px;width:98%;text-align:center;">
												<textarea cols="63" rows="36" wrap="off" id="usertxt" autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"style="width: 940px; background: black; color: white; resize: none;"></textarea>
											</div>
											<div style="margin-top:5px;padding-bottom:10px;width:100%;text-align:center;">
												<input id="edit_node" class="button_gen" type="button" onclick="savefile();" value="保存并重启KP">	
												<input id="edit_node" class="button_gen" type="button" onclick="close_user_rule();" value="返回主界面">
											</div>
										</div>
										<!-- this is the popup area for regular log -->
										<div id="regular_log_status"  class="content_status" style="box-shadow: 3px 3px 10px #000;margin-top: -20px;display: none;">
											<div class="user_title">【Merlin Clash】订阅定时更新日志</div>											
											<div style="margin: 10px 10px 10px 10px;width:98%;text-align:center;overflow:hidden">
												<textarea cols="63" rows="36" wrap="off" id="regular_log" style="width:98%;padding-left:13px;padding-right:33px;border:0px solid #222;font-family:'Lucida Console'; font-size:11px;background: transparent;color:#FFFFFF;outline: none;overflow-x:hidden;" autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"></textarea>
											</div>
											<div style="margin-top:5px;padding-bottom:10px;width:100%;text-align:center;">
												<input class="button_gen" type="button" onclick="close_regular_log();" value="返回主界面">
											</div>
										</div>
										<div id="unblockmusic_log_status"  class="content_status" style="box-shadow: 3px 3px 10px #000;margin-top: -20px;display: none;">
											<div class="user_title">【Merlin Clash】网易云音乐解锁日志</div>											
											<div style="margin: 10px 10px 10px 10px;width:98%;text-align:center;overflow:hidden">
												<textarea cols="63" rows="36" wrap="off" id="unblockmusic_log" style="width:98%;padding-left:13px;padding-right:33px;border:0px solid #222;font-family:'Lucida Console'; font-size:11px;background: transparent;color:#FFFFFF;outline: none;overflow-x:hidden;" autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"></textarea>
											</div>
											<div style="margin-top:5px;padding-bottom:10px;width:100%;text-align:center;">
												<input class="button_gen" type="button" onclick="close_unblockmusic_log();" value="返回主界面">
											</div>
										</div>
										<div id="merlinclash_switch_show" style="margin:-1px 0px 0px 0px;">
											<table style="margin:-1px 0px 0px 0px;" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable" id="merlinclash_switch_table">
												<thead>
												<tr>
													<td colspan="2">开关</td>
												</tr>
												</thead>
												<tr>
												<th id="merlinclash_switch">Merlin Clash开关</th>
													<td colspan="2">
														<div class="switch_field" style="display:table-cell;float: left;">
															<label for="merlinclash_enable">
																<input id="merlinclash_enable" class="switch" type="checkbox" style="display: none;">
																<div class="switch_container" >
																	<div class="switch_bar"></div>
																	<div class="switch_circle transition_style">
																		<div></div>
																	</div>
																</div>
															</label>
														</div>
														<div id="merlinclash_version_show" style="display:table-cell;float: left;position: absolute;margin-left:70px;padding: 5.5px 0px;">
															<a class="hintstyle">
																<i>当前版本：</i>
															</a>
														</div>
														
														<div style="display:table-cell;float: left;margin-left:250px;position: absolute;padding: 5.5px 0px;">
															<a type="button" class="ss_btn" style="cursor:pointer" onclick="get_proc_status()" href="javascript:void(0);">详细状态</a>
														</div>
														<div id="update_button" style="display:table-cell;float: left;position: absolute;margin-left:320px;padding: 5.5px 0px;">
															<span id="updateBtn"></span>
														</div>
													</td>
												</tr>
												<tr>
												<th>程序内核版本</th>
													<td colspan="2">
														<div style="display:table-cell;float: left;margin-left:0px; text-align: right;">
															<div id="merlinclash_core_version">
																<span id="core_state1">clash： UnblockNeteaseMusic： koolproxy：</span>
															</div>
														</div>
													</td>
												</tr>
												
											</table>
											<table style="margin:10px 0px 0px 0px;" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable" >
												<thead>
													<tr>
														<td colspan="2">状态检查</td>
													</tr>
													</thead>
												<tr id="clash_state">
													<th>插件运行状态</th>
														<td>
															<div style="display:table-cell;float: left;margin-left:0px;">
																	<span id="clash_state1">Clash 启动时间 - Waiting...</span>
																	<br/>
																	<span id="clash_state2">Clash 进程状态 - Waiting...</span>
																	<br/>
																	<span id="clash_state3">Clash 看门狗进程状态 - Waiting...</span>
																
															</div>
														</td>
													</tr>
											</table>
											<div id="merlinclash-ip" style="margin:-1px 0px 0px 0px;">
											<table style="margin:-1px 0px 0px 0px;" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable" >																							
												<tr id="ip_state">
													<th>连通性检查</th>
														<td>
															<div style="padding-right: 20px;">
																<div style="display: flex;">
																	<div style="width: 61.8%">IP 地址检查</div>
																	<div style="width: 40%">网站访问检查</div>
																</div>
															</div>
															<div>
																<div style="display: flex;">
																	<div style="width: 61.8%">
																		<p><span class="ip-title">IPIP&nbsp;&nbsp;国内</span>:&nbsp;<span id="ip-ipipnet"></span></p>
																		<p><span class="ip-title">IPAPI&nbsp;海外</span>:&nbsp;<span id="ip-ipapi"></span>&nbsp;<span id="ip-ipapi-geo"></span></p>
																	</div>
																	<div style="width: 40%">
																		<p><span class="ip-title">百度搜索</span>&nbsp;:&nbsp;<span id="http-baidu"></span></p>
																		<p><span class="ip-title">GitHub</span>&nbsp;:&nbsp;<span id="http-github"></span></p>
																		<p><span class="ip-title">YouTube</span>&nbsp;:&nbsp;<span id="http-youtube"></span></p>
																	</div>
																</div>
																<p><span style="float: right">（只检测您浏览器当前状况）</p>
																<p><span style="float: right">Powered by <a href="https://ip.skk.moe" target="_blank">ip.skk.moe</a></span></p>
															</div>
														</td>
												</tr>
											</table>
											</div>
										</div>
										<div id="tablets">
											<table style="margin:10px 0px 0px 0px;border-collapse:collapse" width="100%" height="37px">
												<tr>
													<td cellpadding="0" cellspacing="0" style="padding:0" border="1" bordercolor="#222">
														<input id="show_btn0" class="show-btn0" width="11%" style="cursor:pointer" type="button" value="首页功能" />
														<input id="show_btn1" class="show-btn1" width="11%" style="cursor:pointer" type="button" value="配置文件" />														
														<input id="show_btn2" class="show-btn2" width="11%" style="cursor:pointer" type="button" value="自定规则" />
														<input id="show_btn9" class="show-btn9" width="11%" style="cursor:pointer" type="button" value="黑白郎君" />
														<input id="show_btn3" class="show-btn3" width="11%" style="cursor:pointer" type="button" value="高级模式" />
														<input id="show_btn4" class="show-btn4" width="11%" style="cursor:pointer" type="button" value="附加功能" />
														<input id="show_btn5" class="show-btn5" width="11%" style="cursor:pointer" type="button" value="护网大师" />
                                                        <input id="show_btn8" class="show-btn8" width="11%" style="cursor:pointer" type="button" value="云村解锁" />
														<input id="show_btn7" class="show-btn7" width="11%" style="cursor:pointer" type="button" value="日志记录" />
														<input id="show_btn6" class="show-btn6" width="11%" style="cursor:pointer" type="button" value="当前配置" />
														<input id="show_btn10" class="show-btn10" width="11%" style="cursor:pointer" type="button" value="DC用户" />
                                                    </td>
												</tr>
											</table>
										</div>
										<!--首页功能区-->
										<div id="tablet_0" style="display: none;">
											<div id="merlinclash-content-overview">												
												<div id="merlinclash-yamls" style="margin:-1px 0px 0px 0px;">
													<form name="form1">
													<table style="margin:-1px 0px 0px 0px;" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable" >																							
														<thead>
															<tr>
																<td colspan="2">配置文件</td>
															</tr>
															</thead>
														<tr id="yamlselect">
															<th>配置文件选择</th>
																<td colspan="2">
																	<select id="merlinclash_yamlsel"  name="yamlsel" dataType="Notnull" msg="配置文件不能为空!" class="input_option" ></select>
																</td>
														</tr>
													</table>
													</form>
												</div>
												<div id="merlinclash-mode" style="margin:-1px 0px 0px 0px;">
													<table style="margin:10px 0px 0px 0px;" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable" >																							
														<thead>
															<tr>
																<td colspan="2">运行模式</td>
															</tr>
															</thead>
														<tr id="dns_plan">
															<th><a class="hintstyle" >运行模式 -- 点击切换直接生效</a></th>
																<td colspan="2">
																	<label for="merlinclash_clashmode">
																		<input id="merlinclash_clashmode" type="radio" name="clashmode" value="default" checked="checked">使用配置文件设定
																		<input id="merlinclash_clashmode" type="radio" name="clashmode" value="rule">规则模式
																		<input id="merlinclash_clashmode" type="radio" name="clashmode" value="global">全局模式
																		<input id="merlinclash_clashmode" type="radio" name="clashmode" value="direct">直连模式
																		<input id="merlinclash_clashmode" type="radio" name="clashmode" value="script">脚本模式
																	</label>	
																	<script>
																		$("[name='clashmode']").on("change",
																		function (e) {
																			//console.log($(e.target).val());
																			var mode_tag=$(e.target).val();
																			//alert(dns_tag);
																			PATCH_MODE(mode_tag);
																		}
																		);
																	</script>																
																	
																</td>
														</tr>
													</table>
												</div>
												<div id="merlinclash-dns" style="margin:-1px 0px 0px 0px;">
													<table style="margin:10px 0px 0px 0px;" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable" >																							
														<thead>
															<tr>
																<td colspan="2">DNS方案</td>
															</tr>
															</thead>
														<tr id="dns_plan">
															<th><a class="hintstyle" href="javascript:void(0);" onclick="openmcHint(1)">DNS方案</a></th>
																<td colspan="2">
																	<label for="merlinclash_dnsplan">
																		<input id="merlinclash_dnsplan" type="radio" name="dnsplan" value="rh" checked="checked">默认:Redir-Host&nbsp;&nbsp;&nbsp;&nbsp;
																		<input id="merlinclash_dnsplan" type="radio" name="dnsplan" value="fi">Fake-ip
																	</label>	
																	<p style="color:#FC0">&nbsp;</p>
																	<p style="color:#FC0">1.默认为Redir-Host，兼容性良好，不正确的设置DNS可能被污染；</p>
																	<p style="color:#FC0">2.Fake-ip，拒绝DNS污染。无法获得真实IP，部分游戏/P2P请求可能无法连接；</p>
																	<p style="color:#FC0">3.Clash的DNS工作原理请查阅【<a href="https://github.com/Fndroid/clash_for_windows_pkg/wiki/DNS%E6%B1%A1%E6%9F%93%E5%AF%B9Clash%EF%BC%88for-Windows%EF%BC%89%E7%9A%84%E5%BD%B1%E5%93%8D" target="_blank"><em><u>DNS污染对Clash的影响</u></em></a>】；</p>
																	<p style="color:#FC0">4.各模式DNS可通过附加功能的【<a style="cursor:pointer" onclick="dnsplan()" href="javascript:void(0);"><em><u>DNS编辑</em></u></a>】自行设置。</p>
																</td>
														</tr>
														<tr id="dns_hijack">
															<th>DNS劫持入口</th>
																<td colspan="2">
																	<label for="merlinclash_dnshijack">
																		<input id="merlinclash_dnshijack" type="radio" name="dnshijack" value="front" checked="checked">默认:前置&nbsp;&nbsp;&nbsp;&nbsp;
																		<input id="merlinclash_dnshijack" type="radio" name="dnshijack" value="rear">后置
																	</label>	
																	<p style="color:#FC0">默认，劫持局域网内所有DNS请求，防止因设备自定义DNS造成DNS污染</p>
																	<p style="color:#FC0">若前置DNS解析出错，可以尝试后置方案，设备DNS必须为路由IP</p>
																</td>
														</tr>
													</table>
												</div>
												<table style="margin:10px 0px 0px 0px;" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable" id="merlinclash_switch_table">
														<thead>
														<tr>
															<td colspan="2">Clash管理面板</td>
														</tr>
														</thead>
														<tr id="clash_dashboard">
															<th>面板信息</th>
																<td>
																	<div style="display:table-cell;float: left;margin-left:0px;">																			
																		<span id="dashboard_state2">管理面板</span>&nbsp;|&nbsp;<span id="dashboard_state4">面板密码</span>
																	</div>
																</td>
														</tr>
														<tr>
														<th id="btn-open-clash-dashboard" class="btn btn-primary">访问 Clash 管理面板</th>
															<td colspan="2">
																<div class="merlinclash-btn-container">
																	<a type="button" id="razord" ></a>
																	<a type="button" id="yacd" ></a>
																	<p style="margin-top: 8px">只有在 Clash 正在运行的时候才可以访问 Clash 管理面板</p>
																</div>
															</td>
														</tr>
												</table>
												<table style="margin:10px 0px 0px 0px;" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable" id="merlinclash_switch_table">
													<thead>
													<tr>
														<td colspan="2">排障与重启</td>
													</tr>
													</thead>
														<tr>
															<th id="btn-selectlist" class="btn btn-primary">重建下拉列表</th>
																<td colspan="2">
																	<div class="merlinclash-btn-selectlist">																	
																		<a type="button" style="vertical-align: middle; cursor:pointer;" class="ss_btn" id="selectlist" onclick="selectlist_rebuild()">&nbsp;&nbsp;重建下拉列表&nbsp;&nbsp;</a>												
																	</div>
																</td>
														</tr>
														<tr>
															<th id="btn-iptquicklyrestart" class="btn btn-primary">重建IPTABLES</th>
																<td colspan="2">
																	<div class="merlinclash-btn-iptquicklyrestart">																	
																		<a type="button" style="vertical-align: middle; cursor:pointer;" class="ss_btn" id="iptquicklyrestart" onclick="iptquickly_restart()">&nbsp;&nbsp;重建IPTABLES&nbsp;&nbsp;</a><a class="hintstyle" href="javascript:void(0);" onclick="openmcHint(25)"><em style="color: gold;">【功能说明】</em></a>												
																	</div>
																</td>
														</tr>
														<tr>
															<th id="btn-quicklyrestart" class="btn btn-primary">快速重启</th>
																<td colspan="2">
																	<div class="merlinclash-btn-quicklyrestart">																	
																		<a type="button" style="vertical-align: middle; cursor:pointer;" class="ss_btn" id="quicklyrestart" onclick="quickly_restart()">&nbsp;&nbsp;快速重启&nbsp;&nbsp;</a><a class="hintstyle" href="javascript:void(0);" onclick="openmcHint(7)"><em style="color: gold;">【功能说明】</em></a>														
																	</div>
																</td>
														</tr>
														<tr id="clash_restart_job_tr">
															<th>
																<label >定时重启</label>
															</th>
															<td>
																<select name="select_clash_restart" id="merlinclash_select_clash_restart" onChange="show_job()"  class="input_option" style="margin:-1 0 0 10px;">
																	<option value="1" selected>关闭</option>
																	<option value="5">每隔</option>
																	<option value="2">每天</option>
																	<option value="3">每周</option>
																	<option value="4">每月</option>
																</select>
																<select name="select_clash_restart_day" id="merlinclash_select_clash_restart_day" class="input_option" ></select>
																<select name="select_clash_restart_week" id="merlinclash_select_clash_restart_week" class="input_option" ></select>
																<select name="select_clash_restart_hour"  id="merlinclash_select_clash_restart_hour" class="input_option" ></select>
																<select name="select_clash_restart_minute"  id="merlinclash_select_clash_restart_minute" class="input_option" ></select>
																<select name="select_clash_restart_minute_2"  id="merlinclash_select_clash_restart_minute_2" class="input_option" ></select>
																<input  type="button" id="merlinclash_select_clash_restart_save" class="ss_btn" style="vertical-align: middle; cursor:pointer;" onclick="clash_restart_save();" value="保存设置" />
															</td>
														</tr>
														
												</table>
											</div>
										</div>
										<!--配置文件-->
										<div id="tablet_1" style="display: none;">
											<div id="merlinclash-content-config" style="margin:-1px 0px 0px 0px;">
												<table style="margin:-1px 0px 0px 0px;" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable" >																							
													<thead>
														<tr>
															<td colspan="2">定时订阅&nbsp;|&nbsp;<em style="color:gold;">不支持【手动上传】或【科学上网节点导入】类型配置</em></td>
														</tr>
														</thead>
														<tr id="clash_regular_job_tr">
															<th>
																<label >定时订阅</label>
															</th>
															<td>
																<select name="select_regular_subscribe" id="merlinclash_select_regular_subscribe" onChange="show_job()"  class="input_option" style="margin:0 0 0 10px;">
																	<option value="1" selected>关闭</option>
																	<option value="5">每隔</option>
																	<option value="2">每天</option>
																	<option value="3">每周</option>
																	<option value="4">每月</option>
																</select>
																<select name="select_regular_day" id="merlinclash_select_regular_day" class="input_option" ></select>
																<select name="select_regular_week" id="merlinclash_select_regular_week" class="input_option" ></select>
																<select name="select_regular_hour"  id="merlinclash_select_regular_hour" class="input_option" ></select>
																<select name="select_regular_minute"  id="merlinclash_select_regular_minute" class="input_option" ></select>
																<select name="select_regular_minute_2"  id="merlinclash_select_regular_minute_2" class="input_option" ></select>
																<a type="button" class="ss_btn" style="vertical-align: middle; cursor:pointer" onclick="regular_subscribe_save()" href="javascript:void(0);">&nbsp;&nbsp;保存设置&nbsp;&nbsp;</a>
																
																<a type="button" class="ss_btn" style="vertical-align: middle; cursor:pointer" onclick="get_regular_log()" href="javascript:void(0);">&nbsp;&nbsp;查看日志&nbsp;&nbsp;</a>
																
															</td>
														</tr>
												</table>
												<table  id="clashimport" style="margin:10px 0px 0px 0px;" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable" >
													<thead>
													<tr>
														<td colspan="2">导入Clash配置文件</td>
													</tr>
													</thead>
													<tr>
													<th id="btn-open-clash-configfile" class="btn btn-primary">手动上传Clash配置文件&nbsp;&nbsp;<a class="hintstyle" href="javascript:void(0);" onclick="openmcHint(10)"><em style="color: gold;">【上传必看】</em></a></th>
													<td colspan="2">
														<div class="SimpleNote" style="display:table-cell;float: left; height: 110px; line-height: 110px; margin:-40px 0;">
															<input type="file" id="clashconfig" size="50" name="file"/>
															<span id="clashconfig_info" style="display:none;">完成</span>															
															<a type="button" style="vertical-align: middle; cursor:pointer;" id="clashconfig-btn-upload" class="ss_btn" onclick="upload_clashconfig()" >上传配置文件</a>
														</div>
													</td>
													</tr>														
												</table>
												<table id="uploadcustomrule" style="margin:10px 0px 0px 0px;" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable" >																							
													<thead>
														<tr>
															<td colspan="2">自定订阅ini文件管理&nbsp;&nbsp;<a class="hintstyle" href="javascript:void(0);" onclick="openmcHint(23)"><em style="color: gold;">【使用帮助】</em></a></td>
														</tr>
														</thead>
														<tr>
															<th id="btn-open-clash-ini" class="btn btn-primary">上传ini文件</th>
															<td colspan="2">
																<div class="SimpleNote" style="display:table-cell;float: left; height: 110px; line-height: 110px; margin:-25px 0;">
																	<input type="file" id="clashinifile" size="50" name="file"/>
																	<span id="clashinifile_info" style="display:none;">完成</span>															
																	<a type="button" style="vertical-align: middle; cursor:pointer;" id="clashinifile-btn-upload" class="ss_btn" onclick="upload_clashinifile()" >上传ini配置文件</a>
																</div>
															</td>
														</tr>
														
														<tr id="deliniselect">
															<th>ini文件下载 | 删除</th>
															<td colspan="2">
																<div class="SimpleNote" style="display:table-cell;float: left; height: 110px; line-height: 110px; margin:-40px 0;">
																<select id="merlinclash_delinisel"  name="delinisel" dataType="Notnull" msg="ini文件不能为空!" class="input_option"></select>
																<a type="button" style="vertical-align: middle;" class="ss_btn" style="cursor:pointer" onclick="download_ini_sel('downini')" href="javascript:void(0);">&nbsp;&nbsp;下载ini配置&nbsp;&nbsp;</a>
																<a type="button" style="vertical-align: middle;" class="ss_btn" style="cursor:pointer" onclick="del_ini_sel(30)" href="javascript:void(0);" >&nbsp;&nbsp;删除ini配置&nbsp;&nbsp;</a>
															</div>
															</td>
														</tr>
													<thead>
															<tr>
																<td colspan="2">自定订阅list文件管理</td>
															</tr>
															</thead>
														<tr>
															<th id="btn-open-clash-list" class="btn btn-primary">上传list文件</th>
															<td colspan="2">
																<div class="SimpleNote" style="display:table-cell;float: left; height: 110px; line-height: 110px; margin:-25px 0;">
																	<input type="file" id="clashlistfile" size="50" name="file"/>
																	<span id="clashlistfile_info" style="display:none;">完成</span>															
																	<a type="button" style="vertical-align: middle; cursor:pointer;" id="clashlistfile-btn-upload" class="ss_btn" onclick="upload_clashlistfile()" >上传list规则文件</a>
																</div>
															</td>
														</tr>
														
														<tr id="dellistselect">
															<th>list文件下载 | 删除</th>
															<td colspan="2">
																<div class="SimpleNote" style="display:table-cell;float: left; height: 110px; line-height: 110px; margin:-40px 0;">
																<select id="merlinclash_dellistsel"  name="dellistsel" dataType="Notnull" msg="list文件不能为空!" class="input_option"></select>
																<a type="button" style="vertical-align: middle;" class="ss_btn" style="cursor:pointer" onclick="download_list_sel('downlist')" href="javascript:void(0);">&nbsp;&nbsp;下载list文件&nbsp;&nbsp;</a>
																<a type="button" style="vertical-align: middle;" class="ss_btn" style="cursor:pointer" onclick="del_list_sel(31)" href="javascript:void(0);" >&nbsp;&nbsp;删除list文件&nbsp;&nbsp;</a>
															</div>
															</td>
														</tr>
												</table>
												<table style="margin:10px 0px 0px 0px;" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable" id="merlinclash_switch_table">

													
													<thead>
													<tr>
														<td colspan="2">其他订阅转换Clash规则&nbsp;&nbsp;&nbsp;&nbsp;<a class="hintstyle" href="javascript:void(0);" onclick="openmcHint(6)"><em>【帮助】</em></td>
													</tr>
													</thead>
													<tr id="xiaobai">
														<th><br>小白一键订阅助手
															<br>
															<br><em style="color: gold;">右侧文本框内填入订阅地址，点击开始转换</em>			
															</th>
														<td >
															<div class="SimpleNote" style="display:table-cell;float: left;">
																<label for="merlinclash_links2">
																	<textarea id="merlinclash_links2" placeholder="&nbsp;&nbsp;&nbsp;请输入订阅连接（支持多个订阅地址，回车分行或用'|'隔开）" type="text" style="resize: none; color: #FFFFFF; height:100px; width:400px;background-color:rgba(87,109,115,0.5); font-family: Arial, Helvetica, sans-serif; font-weight:normal; font-size:12px;"></textarea>
																</label>
															</div>
															<div class="SimpleNote" style="display:table-cell;float: left; height: 110px; line-height: 110px; margin:-40px 0;">
																<label style="color: gold;">重命名：</label>
																<input onkeyup="value=value.replace(/[^\w\.\/]/ig,'')" id="merlinclash_uploadrename2" maxlength="20" class="input_25_table" style="width:255px" placeholder="&nbsp;重命名(支持20位数字/字母)">
																<a type="button" style="vertical-align: middle; margin:-10px 10px;" class="ss_btn" style="cursor:pointer" onclick="get_online_yaml2(17)" href="javascript:void(0);">&nbsp;&nbsp;开始转换&nbsp;&nbsp;</a>
															</div>
														</td>
													</tr>
													<tr id="subconverterlocal">
														<th><p id="scoracl"></p>
															<br>
															<br><em style="color: gold;">SS&nbsp;|&nbsp;SSR&nbsp;|&nbsp;V2ray订阅|&nbsp;Trojan订阅</em>
															<br>
															<br>
															<p id="scoracl2"></p>
															<br><em style="color: gold;">规则默认选项并非最优，还需自己摸索</em>																
														</th>
														<td >
															<div class="SimpleNote" style="display:table-cell;float: left;">
																<label for="merlinclash_links3">
																	<textarea id="merlinclash_links3" placeholder="&nbsp;&nbsp;&nbsp;请输入订阅连接（支持多个订阅地址，回车分行或用'|'隔开）" type="text" style="resize: none; color: #FFFFFF; height:100px; width:400px;background-color:rgba(87,109,115,0.5); font-family: Arial, Helvetica, sans-serif; font-weight:normal; font-size:12px;"></textarea>
																</label>
															</div>														
															<div class="SimpleNote" style="display:table-cell;float: left; width: 400px;">
																<label>emoji:</label>																
																<input id="merlinclash_subconverter_emoji" type="checkbox" name="subconverter_emoji" checked="checked">
																<label>启用udp:</label>																
																<input id="merlinclash_subconverter_udp" type="checkbox" name="subconverter_udp">
																<label>节点类型:</label>																
																<input id="merlinclash_subconverter_append_type" type="checkbox" name="subconverter_append_type">
																<label>节点排序:</label>																
																<input id="merlinclash_subconverter_sort" type="checkbox" name="subconverter_sort">
																<label>过滤非法节点:</label>																
																<input id="merlinclash_subconverter_fdn" type="checkbox" name="subconverter_fdn">
																<br>
																<label>跳过证书验证:</label>																
																<input id="merlinclash_subconverter_scv" type="checkbox" name="subconverter_scv">
																<label>TCP Fast Open:</label>																
																<input id="merlinclash_subconverter_tfo" type="checkbox" name="subconverter_tfo">
															</div>
															<div class="SimpleNote" style="display:table-cell;float: left; width: 400px;">
																<p><label>包含节点：</label>
																	<input id="merlinclash_subconverter_include" class="input_25_table" style="width:320px" placeholder="&nbsp;筛选包含关键字的节点名，支持正则">
																</p>
																<br>
																<p><label>排除节点：</label>
																	<input id="merlinclash_subconverter_exclude" class="input_25_table" style="width:320px" placeholder="&nbsp;过滤包含关键字的节点名，支持正则">
																</p>		
																<br>
																<p id="scaddr"><label>后端地址：</label>
																	<input id="merlinclash_subconverter_addr" style="color: #FFFFFF; width: 320px; height: 20px; background-color:rgba(87,109,115,0.5); font-family: Arial, Helvetica, sans-serif; font-weight:normal; font-size:12px;margin:-30px 0;" value="https://api.tshl.us/">
																</p>		
															</div>
															<div class="SimpleNote" style="display:table-cell;float: left; width: 400px; height: 30px; line-height: 30px; ">
																<select id="merlinclash_clashtarget" style="width:100px;margin:0px 0px 0px 0px;text-align:left;padding-left: 0px;" class="input_option">
																	<option value="clash">clash新参数</option>
																	<option value="clashr">clashR新参数</option>						
																</select>
																<select id="merlinclash_acl4ssrsel" style="width:195px;margin:0px 0px 0px 2px;text-align:left;padding-left: 0px;" class="input_option">
																	<option value="ZHANG">Merlin Clash_常规规则</option>
																	<option value="ZHANG_NoAuto">Merlin Clash_常规无测速</option>
																	<option value="ZHANG_Media">Merlin Clash_多媒体全量</option>
																	<option value="ZHANG_Media_NoAuto">Merlin Clash_多媒体全量无测速</option>
																	<option value="ZHANG_Media_Area_UrlTest">Merlin Clash_多媒体全量分地区测速</option>
																	<option value="ZHANG_Media_Area_FallBack">Merlin Clash_多媒体全量分地区故障转移</option>
																	<option value="ACL4SSR_Online">Online默认版_分组比较全</option>
																	<option value="ACL4SSR_Online_AdblockPlus">AdblockPlus_更多去广告</option>	
																	<option value="ACL4SSR_Online_NoAuto">NoAuto_无自动测速</option>	
																	<option value="ACL4SSR_Online_NoReject">NoReject_无广告拦截规则</option>	
																	<option value="ACL4SSR_Online_Mini">Mini_精简版</option>	
																	<option value="ACL4SSR_Online_Mini_AdblockPlus">Mini_AdblockPlus_精简版更多去广告</option>	
																	<option value="ACL4SSR_Online_Mini_NoAuto">Mini_NoAuto_精简版无自动测速</option>
																	<option value="ACL4SSR_Online_Mini_Fallback">Mini_Fallback_精简版带故障转移</option>	
																	<option value="ACL4SSR_Online_Mini_MultiMode">Mini_MultiMode_精简版自动测速故障转移负载均衡</option>	
																	<option value="ACL4SSR_Online_Full">Full全分组_重度用户使用</option>
																	<option value="ACL4SSR_Online_Full_NoAuto">Full全分组_无自动测速</option>
																	<option value="ACL4SSR_Online_Full_AdblockPlus">Full全分组_更多去广告</option>
																	<option value="ACL4SSR_Online_Full_Netflix">Full全分组_奈飞全量</option>
																	<option value="ACL4SSR_Online_Full_Google">Full全分组_谷歌细分</option>
																	<option value="ACL4SSR_Online_Full_MultiMode">Full全分组_多模式</option>
																	<option value="ACL4SSR_Online_Mini_MultiCountry">Full全分组_多国家地区</option>	
																</select>
																<select id="merlinclash_acl4ssrsel_cus" style="width:195px;margin:0px 0px 0px 2px;text-align:left;padding-left: 0px;display: none;" class="input_option">			
																</select>
																<input id="merlinclash_customrule_cbox" type="checkbox" name="merlinclash_customrule_cbox"><span id="merlinclash_customrule_cbox_span">&nbsp;使用自定订阅</span>
																<script>
																	$("[name='merlinclash_customrule_cbox']").on("change",
																	function (e) {
																		var mode_tag=$(e.target).val();
																		set_rulemode();
																	}
																	);
																</script>
																<input id="merlinclash_cdn_cbox" type="checkbox" name="merlinclash_cdn_cbox"><span id="merlinclash_cdn_cbox_span">&nbsp;CDN订阅</span>
															</div>
															<div class="SimpleNote" style="display:table-cell;float: left; height: 30px; line-height: 30px; ">
																<label style="color: gold;">远程配置：</label>
																<input id="merlinclash_uploadiniurl" class="input_25_table" style="width:255px" placeholder="&nbsp;请输入文件URL地址">
																<input id="merlinclash_customurl_cbox" type="checkbox" name="merlinclash_customurl_cbox"><span>&nbsp;勾选使用</span>
															</div>
															<div class="SimpleNote" style="display:table-cell;float: left; height: 30px; line-height: 30px; ">
																<label style="color: gold;">重命名：</label>
																<input onkeyup="value=value.replace(/[^\w\.\/]/ig,'')" id="merlinclash_uploadrename4" maxlength="20" class="input_25_table" style="width:255px" placeholder="&nbsp;重命名(支持20位数字/字母)">
																<a type="button" style="vertical-align: middle; margin:-10px 10px;" class="ss_btn" style="cursor:pointer" onclick="get_online_yaml3(16)" href="javascript:void(0);">&nbsp;&nbsp;开始转换&nbsp;&nbsp;</a>
															</div>
														</td>
													</tr>
													<tr id="clashyamldown">
														<th>
															<br><a class="hintstyle" href="javascript:void(0);" onclick="openmcHint(14)">Clash-Yaml配置下载</a>
															<br>
															<br><em style="color: gold;">Clash专用订阅&nbsp;|&nbsp;ACL4SSR等转换订阅</em>
														</th>
														<td >
															<div class="SimpleNote" style="display:table-cell;float: left;">
																<label for="merlinclash_links">
																	<textarea id="merlinclash_links" placeholder="&nbsp;&nbsp;&nbsp;请输入订阅连接（只支持单个订阅地址）" type="text" style="resize: none; color: #FFFFFF; height:100px; width:400px;background-color:rgba(87,109,115,0.5); font-family: Arial, Helvetica, sans-serif; font-weight:normal; font-size:12px;"></textarea>
																</label>
															</div>
															<div class="SimpleNote" style="display:table-cell;float: left; height: 110px; line-height: 110px; margin:-40px 0;">
																<label style="color: gold;">重命名：</label>		
																<input onkeyup="value=value.replace(/[^\w\.\/]/ig,'')" id="merlinclash_uploadrename" maxlength="20" class="input_25_table" style="width:255px" placeholder="&nbsp;重命名,支持20位数字/字母">
																<a type="button" style="vertical-align: middle; margin:-10px 10px;" class="ss_btn" style="cursor:pointer" onclick="get_online_yaml(2)" href="javascript:void(0);">&nbsp;&nbsp;Clash订阅&nbsp;&nbsp;</a>
																</div>
														</td>
													</tr>
												</table>
												<table id="ssimport" style="margin:10px 0px 0px 0px;" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable" >																							
													<thead>
														<tr>
															<td colspan="2">导入【<a href=" ./Module_shadowsocks.asp" target="_blank"><em style="color:gold;">科学上网</em></a> 】节点</td>
														</tr>
														</thead>
													<tr id="ssconvert">
														<th>读取科学上网节点，转换为Clash规则</th>
															<td colspan="2">
																<div class="SimpleNote" style="display:table-cell;float: left; height: 110px; line-height: 110px; margin:-40px 0;">
																<label style="color: gold;">重命名：</label>	
																<input onkeyup="value=value.replace(/[^\w\.\/]/ig,'')" id="merlinclash_uploadrename3" maxlength="20" class="input_25_table" style="width:255px" placeholder="&nbsp;转换文件命名,支持20位数字/字母">
																<label for="merlinclash_ssconvert_btn">
																	<a type="button" style="vertical-align: middle; margin:-10px 10px;" class="ss_btn" style="cursor:pointer" onclick="ssconvert(6)" href="javascript:void(0);">&nbsp;&nbsp;一键转换&nbsp;&nbsp;</a>																
																</label>
															</div>
															</td>
													</tr>
												</table>
												
												<form name="form1">
													<table style="margin:10px 0px 0px 0px;" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable" >																							
														<thead>
															<tr>
																<td colspan="2">下载&nbsp;|&nbsp;删除&nbsp;|&nbsp;更新配置文件</td>
															</tr>
															</thead>
														<tr id="delyamlselect">
															<th>配置文件选择&nbsp;&nbsp;<span id="clash_yamlsel">当前配置为：</span></th>
															<td colspan="2">
																<div class="SimpleNote" style="display:table-cell;float: left; height: 110px; line-height: 110px; margin:-40px 0;">
																<select id="merlinclash_delyamlsel"  name="delyamlsel" dataType="Notnull" msg="配置文件不能为空!" class="input_option"></select>
																<a type="button" style="vertical-align: middle;" class="ss_btn" style="cursor:pointer" onclick="download_yaml_sel('downyaml')" href="javascript:void(0);">&nbsp;&nbsp;下载配置&nbsp;&nbsp;</a>
																<a type="button" style="vertical-align: middle;" class="ss_btn" style="cursor:pointer" onclick="del_yaml_sel(0)" href="javascript:void(0);" >&nbsp;&nbsp;删除配置&nbsp;&nbsp;</a>
																<a type="button" style="vertical-align: middle;" class="ss_btn" style="cursor:pointer" onclick="update_yaml_sel(0)" href="javascript:void(0);" >&nbsp;&nbsp;更新配置&nbsp;&nbsp;</a>
															</div>
															</td>
														</tr>
													</table>
												</form>
												
											</div>				
										</div>
										<!--日志记录-->
										<div id="tablet_7" style="display: none;">
											<div id="merlinclash-notelog" style="margin:-1px 0px 0px 0px;">
												<table style="margin:-1px 0px 0px 0px;" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable" >																							
													<thead>
														<tr>
															<td colspan="2"><em style="color: gold;">节点恢复日志/记录</em></td>
														</tr>
														</thead>
													</table>
												<div id="nodes_content" style="margin-top:0px; width:750px; height: 360px;">
													<textarea class="sbar" cols="63" rows="36" wrap="on" readonly="readonly" id="nodes_content1" style="margin: 0px; width: 709px; height: 350px; resize: none;"></textarea>
												</div>
											
											</div>	
			
											<div id="merlinclash-OPLOG" style="margin:5px 0px 0px 0px;">
												<table style="margin:5px 0px 0px 0px;" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable" >																							
													<thead>
														<tr>
															<td colspan="2"><em style="color: gold;">操作日志</em></td>
														</tr>
														</thead>
													</table> 
												<div id="log_content" style="margin-top:-1px;overflow:hidden;">
													<textarea class="sbar" cols="63" rows="36" wrap="on" readonly="readonly" id="log_content1" style="margin: 0px; width: 709px; height: 800px; resize: none;"></textarea>
												</div>
														
											</div>
										</div>
											
										
										<!--自定规则-->
										<div id="tablet_2" style="display: none;">
											<div id="merlinclash_acl_table">
											</div>
											<div id="clash_script_area">										
												<table style="margin:10px 0px 0px 0px;" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable" id="merlinclash_script_table">
													<thead>
													<tr>
														<td colspan="2">Script&nbsp;&nbsp;编辑 -- <em style="color: gold;">【不懂勿动！编辑完成后需点击“修改提交”保存配置，下次启动Merlin Clash时生效】|【开启编辑：<input id="merlinclash_scriptedit_check" class="barcodeSavePrint" type="checkbox" name="scriptedit_check" >】</em></td>
													</tr>
													<script>
														$(function () {
															$(".barcodeSavePrint").click(function () {
																if (this.checked==true){
																	document.getElementById("merlinclash_script_edit_content1").readOnly = false

																}else{
																	document.getElementById("merlinclash_script_edit_content1").readOnly = true
																}
															})
														})
													</script>
													</thead>
												</table>
												<table style="margin:-1px 0px 0px 0px;" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable" id="merlinclash_dnsfiles_content_table">
													<tr id="script_edit_tr">
														<th>Script脚本编辑</th>
															<td>
																<input class="ss_btn" type="button" onclick="scriptchange()" value="修改提交">
																
															</td>
													</tr>
												</table>
												<table style="margin:-1px 0px 0px 0px;" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable">
													<div id="merlinclash_script_edit_content" style="margin-top:-1px;overflow:hidden;">
														<textarea rows="7" wrap="on" id="merlinclash_script_edit_content1" name="script_edit_content1" style="margin: 0px; width: 709px; height: 150px; resize: none;" readonly="true"></textarea>
													</div>
												</table>
											</div>	
											<table style="margin:10px 0px 0px 0px;" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable" id="merlinclash_switch_table">
												<thead>
												<tr>
													<td colspan="2">备份/恢复</td>
												</tr>
												</thead>
												<tr>
													<th id="btn-open-clash-dashboard" class="btn btn-primary">备份自定义规则</th>
													<td colspan="2">
														<a type="button" style="vertical-align: middle; cursor:pointer;" id="clashrestorerule-btn-download" class="ss_btn" onclick="down_clashrestorerule(1)" >导出自定义规则</a>
													</td>
												</tr>
												<tr>
												<th id="btn-open-clash-dashboard" class="btn btn-primary">恢复自定义规则</th>
												<td colspan="2">
													<div class="SimpleNote" style="display:table-cell;float: left; height: 110px; line-height: 110px; margin:-40px 0;">
														<input type="file" style="width: 200px;margin: 0,0,0,0px;" id="clashrestorerule" size="50" name="file"/>
														<span id="clashrestorerule_info" style="display:none;">完成</span>															
														<a type="button" style="vertical-align: middle; cursor:pointer;" id="clashrestorerule-btn-upload" class="ss_btn" onclick="upload_clashrestorerule()" >恢复自定义规则</a>
													</div>
												</td>
												</tr>														
											</table>
																							
											<div id="ACL_note" style="margin:10px 0 0 5px">
											
											<div><i>&nbsp;&nbsp;<em>1.更换yaml配置文件后，请手动删除上一个配置文件的自定义规则！否则Clash可能无法正常启动。</em></i></div>
											<div><i>&nbsp;&nbsp;2.编辑规则有风险，请勿在没完全搞懂的情况下，胡乱尝试。</i></div>
											<div><i>&nbsp;&nbsp;3.如果您添加的规则不符合Clash的标准，进程会无法启动。请删除所有自定义规则，重新启动。</i></div>
											<div><i>&nbsp;&nbsp;4.如果新加规则和老规则冲突，则会按照新规则执行。</i></div>
											<div><i>&nbsp;&nbsp;5.【访问控制】写法示例：</i></div>
											<div><i>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;让某设备不过代理：类型：<em>SRC-IP-CIDR</em>，内容：<em>192.168.50.201/32</em>（IP必须有掩码位），连接方式：<em>DIRECT</em>（大写）</i></div>
											<div><i>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;禁止某端口联网：类型：<em>DST-PORT</em>，内容：<em>7777</em>（端口号），连接方式：<em>REJECT</em>（大写）</i></div>
											<div><i>&nbsp;&nbsp;6.更多说明请点击表头查看，或者参阅Clash的【<a href="https://lancellc.gitbook.io/clash/clash-config-file/rules" target="_blank"><em><u>开发文档</u></em></a>】。</i></div>
											<div><i>&nbsp;</i></div>
											</div>
										</div>
										<!--访问控制-->
										<div id="tablet_9" style="display: none;">
											<div id="nokpacllist">
												<table style="margin:-1px 0px 0px 0px;" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable" id="merlinclash_switch_table">
													<thead>
													<tr>
														<td colspan="2">访问控制</td>
													</tr>
													</thead>
												</table>	
												<div id="merlinclash_nokpacl_table">
												</div>
											</div>
											<table style="margin:10px 0px 0px 0px;" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable" id="merlinclash_switch_table">
												<thead>
												<tr>
													<td colspan="2">备份/恢复</td>
												</tr>
												</thead>
												<tr>
													<th id="btn-open-clash-dashboard" class="btn btn-primary">备份访问控制</th>
													<td colspan="2">
														<a type="button" style="vertical-align: middle; cursor:pointer;" id="passdevice-btn-download" class="ss_btn" onclick="down_passdevice(1)" >导出访问控制</a>
													</td>
												</tr>
												<tr>
												<th id="btn-open-clash-dashboard" class="btn btn-primary">恢复访问控制</th>
												<td colspan="2">
													<div class="SimpleNote" style="display:table-cell;float: left; height: 110px; line-height: 110px; margin:-40px 0;">
														<input type="file" style="width: 200px;margin: 0,0,0,0px;" id="passdevice" size="50" name="file"/>
														<span id="passdevice_info" style="display:none;">完成</span>															
														<a type="button" style="vertical-align: middle; cursor:pointer;" id="passdevice-btn-upload" class="ss_btn" onclick="upload_passdevice()" >恢复访问控制</a>
													</div>
												</td>
												</tr>														
											</table>												
											<div id="DEVICE_note" style="margin:10px 0 0 5px">
											<div><i>&nbsp;&nbsp;1.本功能通过iptables实现设备黑白名单，优先级高于Clash访问控制规则；<br>
											&nbsp;&nbsp;2.如果某些设备开启Clash无法正常联网，可尝试使用此功能；<br>
											&nbsp;&nbsp;3.访问控制通过MAC地址甄别设备，请关闭iPhone等设备的随机MAC地址功能。<br>
											&nbsp;&nbsp;4.当KoolProxy开启时，访问控制通过IP地址甄别设备，请在【<a href="./Advanced_DHCP_Content.asp" target="_blank"><em><u>DHCP设置</u></em></a>】绑定需要控制设备的IP地址；<br>
											&nbsp;&nbsp;5.如果需要自定义端口范围，适用英文逗号和冒号，参考格式：80,443,5566:6677,7777:8888。<br>
											</i></div>
											<div><i>&nbsp;</i></div>
											</div>
										</div>
										<!--高级模式-->
										<div id="tablet_3" style="display: none;">
											<!--补丁更新-->
											<div id="merlinclash-patch" style="margin:-1px 0px 0px 0px;">
												<table style="margin:-1px 0px 0px 0px;" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable" >																							
													<thead>
														<tr>
															<td colspan="2">补丁更新</td>
														</tr>
														</thead>
														<tr>
															<th>安装补丁&nbsp;<span id="patch_version">【已装补丁版本】：</span></th>
																<td colspan="2">
																	<div class="SimpleNote" style="display:table-cell;float: left; height: 110px; line-height: 110px; margin:-40px 0;">
																		<input type="file" id="clashpatch" size="50" name="file"/>
																		<span id="clashpatch_upload" style="display:none;">完成</span>															
																		<a type="button" style="vertical-align: middle; cursor:pointer;" id="clashpatch-btn-upload" class="ss_btn" onclick="upload_clashpatch()" >上传补丁</a>
																		
																	</div>
																</td>		
														</tr>
												</table>
												<table style="margin:10px 0px 0px 0px;" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable" id="merlinclash_switch_table">
													<thead>
													<tr>
														<td colspan="2">Merlin Clash&nbsp;&nbsp;看门狗</td>
													</tr>
													</thead>
													<tr>
													<th>Clash 看门狗开关</th>
														<td colspan="2">
															<div class="switch_field" style="display:table-cell;float: left;">
																<label for="merlinclash_watchdog">
																	<input id="merlinclash_watchdog" class="switch" type="checkbox" style="display: none;">
																	<div class="switch_container" >
																		<div class="switch_bar"></div>
																		<div class="switch_circle transition_style">
																			<div></div>
																		</div>
																	</div>
																</label>
															</div>
															<div class="SimpleNote" id="head_illustrate">
																<p>进程守护工具，根据设定的时间，周期性检查 Clash 进程是否存在，如果 Clash 进程丢失则会自动重新拉起。</p>
																<p style="color:gold; margin-top: 8px">注意：Clash本身运行稳定，通常不必开启该功能。</p>
															</div>
														</td>
													</tr>
															<!--看门狗检查间隔-->
													<tr>
															<th>自定义检查时间</th>
																<td colspan="2">
																	<div class="SimpleNote" id="head_illustrate">
																		<input onkeyup="this.value=this.value.replace(/[^1-9]+/,'2')" id="merlinclash_watchdog_delay_time" maxlength="2" class="input_6_table" value="2" ><span>&nbsp;分钟</span>															
																		<input  type="button" id="merlinclash_clash_watchdog_save" class="ss_btn" style="vertical-align: middle; cursor:pointer;" onclick="clash_watchdog_save();" value="保存设置" />
															
																	</div>
																</td>		
														</tr>
												
												</table>
											</div>
											<!--Merlin Clash透明代理-->
											<div id="noipt" style="margin:-1px 0px 0px 0px;">
												<table style="margin:10px 0px 0px 0px;" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable" >																							
													<thead>
														<tr>
															<td colspan="2">Merlin Clash&nbsp;&nbsp;关闭透明代理 | <em style="color: gold">关闭后只能通过http/socks连接</em></td>
														</tr>
														</thead>
														<tr>
															<th>关闭透明代理</th>
															<td colspan="2">
																<div class="switch_field" style="display:table-cell;float: left;">
																<label for="merlinclash_closeproxy">
																	<input id="merlinclash_closeproxy" type="checkbox" name="closeproxy" class="switch" style="display: none;">
																	<div class="switch_container" >
																		<div class="switch_bar"></div>
																		<div class="switch_circle transition_style">
																			<div></div>
																		</div>
																	</div>
																</label>
																
															</div>
															</td>		
														</tr>
												</table>
											</div>
											<!--Merlin Clash启动参数-->
											<div id="merlinclash-autodelay" style="margin:-1px 0px 0px 0px;">
												<table style="margin:10px 0px 0px 0px;" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable" >																							
													<thead>
														<tr>
															<td colspan="2">Merlin Clash&nbsp;&nbsp;启动参数</td>
														</tr>
														</thead>
														<tr>
															<th><a class="hintstyle" href="javascript:void(0);" onclick="openmcHint(20)">开机自启推迟时间</a></th>
																<td colspan="2">
																	<div class="SimpleNote" id="head_illustrate">
																		<input id="merlinclash_auto_delay_time" maxlength="3" class="input_6_table" value="120" ><span>&nbsp;秒&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span>	
																		<input id="merlinclash_auto_delay_cbox" type="checkbox" name="merlinclash_auto_delay_cbox"><span>&nbsp;勾选后提交生效</span>
																	</div>
																	<script>
																		$("#merlinclash_auto_delay_time").on("keyup",function(){
																			$(this).val($(this).val().replace(/[^0-9]+/,''));
																			if($(this).val().length == 1){
																				$(this).val() == '0' ? $(this).val('2') : $(this).val();
																			}
																		});
																		$("#merlinclash_auto_delay_time").on("keydown",function(){
																			$(this).val($(this).val().replace(/[^0-9]+/,''));
																			if($(this).val().length == 1){
																				$(this).val() == '0' ? $(this).val('2') : $(this).val();
																			}
																		});
																	</script>
																</td>		
														</tr>
														<!--启动日志检查延迟-->
														<tr>
															<th><a class="hintstyle" href="javascript:void(0);" onclick="openmcHint(13)">检查日志延迟时间</a></th>
																<td colspan="2">
																	<div class="SimpleNote" id="head_illustrate">
																		<input id="merlinclash_check_delay_time" maxlength="2" class="input_6_table" value="2" ><span>&nbsp;秒&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span>															
																		<input id="merlinclash_check_delay_cbox" type="checkbox" name="merlinclash_check_delay_cbox"><span>&nbsp;勾选后提交生效</span>
																	</div>
																	<script>
																		$("#merlinclash_check_delay_time").on("keyup",function(){
																			$(this).val($(this).val().replace(/[^0-9]+/,''));
																			if($(this).val().length == 1){
																				$(this).val() == '0' ? $(this).val('2') : $(this).val();
																			}
																		});
																		$("#merlinclash_check_delay_time").on("keydown",function(){
																			$(this).val($(this).val().replace(/[^0-9]+/,''));
																			if($(this).val().length == 1){
																				$(this).val() == '0' ? $(this).val('2') : $(this).val();
																			}
																		});
																	</script>
																</td>		
														</tr>
														<!--启动时简化日志-->
													    <tr id="start_log">
															<th>启动时简化日志</th>
																<td colspan="2">
																	<div class="switch_field" style="display:table-cell;float: left;">
																	<label for="merlinclash_startlog">
																		<input id="merlinclash_startlog" type="checkbox" name="cir" class="switch" style="display: none;">
																		<div class="switch_container" >
																			<div class="switch_bar"></div>
																			<div class="switch_circle transition_style">
																				<div></div>
																			</div>
																		</div>
																	</label>
																</div>
																</td>
															</tr>
														<!--绕行大陆IP-->
													    <tr id="china_ip_route">
														<th><a class="hintstyle" href="javascript:void(0);" onclick="openmcHint(17)">大陆IP不经过Clash</a></th>
															<td colspan="2">
																<div class="switch_field" style="display:table-cell;float: left;">
																<label for="merlinclash_cirswitch">
																	<input id="merlinclash_cirswitch" type="checkbox" name="cir" class="switch" style="display: none;">
																	<div class="switch_container" >
																		<div class="switch_bar"></div>
																		<div class="switch_circle transition_style">
																			<div></div>
																		</div>
																	</div>
																</label>
																
															</div>
															</td>
														</tr>
														<!--DNS-->
														<tr id="dns_goclsh">
														<th>代理路由DNS -- <em style="color: gold;">仅Redir-Host模式有效</em></th>
															<td colspan="2">
																<div class="switch_field" style="display:table-cell;float: left;">
																<label for="merlinclash_dnsgoclash">
																	<input id="merlinclash_dnsgoclash" type="checkbox" name="dnsgoclash" class="switch" style="display: none;">
																	<div class="switch_container" >
																		<div class="switch_bar"></div>
																		<div class="switch_circle transition_style">
																			<div></div>
																		</div>
																	</div>
																</label>
																</div>
															</td>
														</tr>
														<!--清除自定义DNS-->
														<tr id="dns_clear">
															<th>清除路由自定义DNS</th>
																<td colspan="2">
																	<div class="switch_field" style="display:table-cell;float: left;">
																	<label for="merlinclash_dnsclear">
																		<input id="merlinclash_dnsclear" type="checkbox" name="dnsclear" class="switch" style="display: none;">
																		<div class="switch_container" >
																			<div class="switch_bar"></div>
																			<div class="switch_circle transition_style">
																				<div></div>
																			</div>
																		</div>
																	</label>
																	</div>
																</td>
															</tr>
												</table>
											</div>
											<!--Merlin Clash自定义参数-->
											<div id="clash_cusport_area">
												<table style="margin:10px 0px 0px 0px;" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable" >																							
													<thead>
														<tr>
															<td colspan="2">Merlin Clash&nbsp;&nbsp;自定义端口
																<input id="merlinclash_custom_cbox" type="checkbox" name="merlinclash_custom_cbox"><span>&nbsp;勾选后提交生效</span>
															</td>
														</tr>
													</thead>
														<tr>
															<th>port:</th>
															<td colspan="2">
																<div class="SimpleNote" id="head_illustrate">
																	<input onkeyup="this.value=this.value.replace(/[^1-9]+/,'0')" id="merlinclash_cus_port" maxlength="5" class="input_6_table" value="3333" >
																	<em style="color: gold;">(默认值：3333)</em>															
																</div>
															</td>		
														</tr>
														<tr>
															<th>socks-port:</th>
															<td colspan="2">
																<div class="SimpleNote" id="head_illustrate">
																	<input onkeyup="this.value=this.value.replace(/[^1-9]+/,'0')" id="merlinclash_cus_socksport" maxlength="5" class="input_6_table" value="23456" >
																	<em style="color: gold;">(默认值：23456)</em>																														
																</div>
															</td>		
														</tr>
														<tr>
															<th>redir-port:</th>
															<td colspan="2">
																<div class="SimpleNote" id="head_illustrate">
																	<input onkeyup="this.value=this.value.replace(/[^1-9]+/,'0')" id="merlinclash_cus_redirsport" maxlength="5" class="input_6_table" value="23457" >
																	<em style="color: gold;">(默认值：23457)</em>																														
																</div>
															</td>		
														</tr>
														<tr>
															<th>tproxy-port:</th>
															<td colspan="2">
																<div class="SimpleNote" id="head_illustrate">
																	<input onkeyup="this.value=this.value.replace(/[^1-9]+/,'0')" id="merlinclash_cus_tproxyport" maxlength="5" class="input_6_table" value="23458" >
																	<em style="color: gold;">(默认值：23458)</em>																														
																</div>
															</td>		
														</tr>
														<tr>
															<th>dns监听端口:</th>
															<td colspan="2">
																<div class="SimpleNote" id="head_illustrate">
																	<input onkeyup="this.value=this.value.replace(/[^1-9]+/,'0')" id="merlinclash_cus_dnslistenport" maxlength="5" class="input_6_table" value="23453" >
																	<em style="color: gold;">(默认值：23453)</em>																														
																</div>
															</td>		
														</tr>
														<tr>
															<th>管理面板访问端口:</th>
															<td colspan="2">
																<div class="SimpleNote" id="head_illustrate">
																	<input onkeyup="this.value=this.value.replace(/[^1-9]+/,'0')" id="merlinclash_cus_dashboardport" maxlength="5" class="input_6_table" value="9990" >
																	<em style="color: gold;">(默认值：9990)</em>																														
																</div>
															</td>		
														</tr>
												</table>
											</div>
											<!--Google Home-->
											<div id="merlinclash-googlehome" style="margin:-1px 0px 0px 0px;">
												<table style="margin:10px 0px 0px 0px;" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable">
													<thead>
													<tr>
														<td colspan="2">Google Home&nbsp;&nbsp;支持</td>
													</tr>
													</thead>
													<tr id="googlehome">	
														<th>开启Google Home支持</th>
														<td colspan="2">
															<div class="switch_field" style="display:table-cell;float: left;">
															<label for="merlinclash_googlehomeswitch">
																<input id="merlinclash_googlehomeswitch" type="checkbox" name="googlehome" class="switch" style="display: none;">
																<div class="switch_container" >
																	<div class="switch_bar"></div>
																	<div class="switch_circle transition_style">
																		<div></div>
																	</div>
																</div>
															</label>													
														</div>
														</td>
													</tr>							
												</table>	
											</div>
											<!--测速延迟容差设定-->
											<div id="merlinclash-urltestTolerance" style="margin:-1px 0px 0px 0px;">
												<table style="margin:10px 0px 0px 0px;" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable" >																							
													<thead>
														<tr>
															<td colspan="2">值设定 <a class="hintstyle" href="javascript:void(0);" onclick="openmcHint(16)"><em style="color: gold;">【说明】</em></a></td>
														</tr>
														</thead>
														<tr>
															<th>自定义测速时间值(单位:秒)</th>
																<td colspan="2">
																	<div class="SimpleNote" id="head_illustrate">
																		<select id="merlinclash_intervalsel" style="width:60px;margin:0px 0px 0px 2px;text-align:left;padding-left: 0px;" class="input_option">
																			<option value="60">60</option>
																			<option value="120">120</option>
																			<option value="180">180</option>
																			<option value="240">240</option>
																			<option value="300" selected>300</option>
																			<option value="360">360</option>
																			<option value="420">420</option>
																			<option value="480">480</option>
																			<option value="540">540</option>
																			<option value="600">600</option>						
																		</select>
																		<input id="merlinclash_interval_cbox" type="checkbox" name="merlinclash_interval_cbox"><span>&nbsp;勾选后提交生效</span>
																	</div>
																</td>		
														</tr>
														<tr>
															<th>自定义容差值(单位:毫秒)</th>
																<td colspan="2">
																	<div class="SimpleNote" id="head_illustrate">
																		<select id="merlinclash_urltestTolerancesel" style="width:60px;margin:0px 0px 0px 2px;text-align:left;padding-left: 0px;" class="input_option">
																			<option value="100">100</option>
																			<option value="200">200</option>
																			<option value="300">300</option>
																			<option value="500">500</option>
																			<option value="1000">1000</option>						
																		</select>
																		<input id="merlinclash_urltestTolerance_cbox" type="checkbox" name="merlinclash_urltestTolerance_cbox"><span>&nbsp;勾选后提交生效</span>
																	</div>
																</td>		
														</tr>
												</table>
											</div>

											<div id="merlinclash-dashboard" style="margin:-1px 0px 0px 0px;">
											<table style="margin:10px 0px 0px 0px;" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable">
												<thead>
												<tr>
													<td colspan="2">管理面板设定 -- <em style="color: gold;">【开启面板公网访问请设置复杂密码，并设置<a href="./Advanced_VirtualServer_Content.asp" target="_blank"><em>端口转发</em></a>】</em><a class="hintstyle" href="javascript:void(0);" onclick="openmcHint(12)"><em>【教程】</em></a></td>
												</tr>
												</thead>
												<tr id="dashboard">	
												<th>开启管理面板公网访问</th>
												<td colspan="2">
													<div class="switch_field" style="display:table-cell;float: left;">
													<label for="merlinclash_dashboardswitch">
														<input id="merlinclash_dashboardswitch" type="checkbox" name="dashboard" class="switch" style="display: none;">
														<div class="switch_container" >
															<div class="switch_bar"></div>
															<div class="switch_circle transition_style">
																<div></div>
															</div>
														</div>
													</label>													
												</div>
												</td>
												</tr>												
												<tr>
													<th>管理面板密码</th>
														<td colspan="2">
															<div class="SimpleNote" id="head_illustrate">																	
																<input id="merlinclash_dashboard_secret" class="input_15_table" placeholder="">																
															</div>
														</td>		
												</tr>
																					
											</table>	
											</div>
											<div id="iptables_schedule" style="margin:-1px 0px 0px 0px;">
												<table style="margin:10px 0px 0px 0px;" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable" >	
													<thead>
														<tr>
															<td colspan="2">Iptables方案</td>
														</tr>
													</thead>
													<tr id="Iptables_sel">
														<th><a class="hintstyle" >Iptables方案</a></th>
														<td colspan="2">
															<label for="merlinclash_iptablessel">
																<input id="merlinclash_iptablessel" type="radio" name="iptablessel" value="fangan1" checked="checked">默认:方案一
																<input id="merlinclash_iptablessel" type="radio" name="iptablessel" value="fangan2">方案二
															</label>
															<p style="color:#FC0">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;方案二为1225版本方案</p>
															<p style="color:#FC0">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;1.方案一无法联网时再尝试方案二</p>
															<p style="color:#FC0">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;2.已知方案二，开启TPROXY-TCP/TCP&UDP且开启大陆绕行，</p>
															<p style="color:#FC0">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;OPENVPN回程无法访问国内网站</p>
															<p style="color:#FC0">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;3.方案二开启TPROXY代理，远程桌面、IPSEC将不可用</p>
														</td>
													</tr>
												</table>
											</div>
											<div id="tproxy" style="margin:-1px 0px 0px 0px;">
												<table style="margin:10px 0px 0px 0px;" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable" >																							
													<thead>
														<tr>
															<td colspan="2">Tproxy转发&nbsp;|&nbsp;IPV6模式<em style="color: gold;">使用本功能请关闭护网大师</em></td>
														</tr>
														</thead>
													<tr id="Tproxy_plan">
															<th><a class="hintstyle" >Tproxy模式</a></th>
															<td colspan="2">
																<label for="merlinclash_tproxymode">
																	<input id="merlinclash_tproxymode" type="radio" name="tproxymode" value="closed" checked="checked">默认:关闭
																	<input id="merlinclash_tproxymode" type="radio" name="tproxymode" value="tcp">仅开启TCP转发
																	<input id="merlinclash_tproxymode" type="radio" name="tproxymode" value="udp">仅开启UDP转发
																	<input id="merlinclash_tproxymode" type="radio" name="tproxymode" value="tcpudp">同时开启TCP&UDP
																</label>														
																<p style="color:#FC0">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;1.默认为关闭</p>
																<p style="color:#FC0">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;2.使用tproxy开启TCP转发实现透明代理</p>
																<p style="color:#FC0">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;3.使用tproxy开启UDP转发，类似小飞机的游戏模式</p>
																<p style="color:#FC0">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;4.使用tproxy开启TCP,UDP转发做透明代理</p>
															</td>
													</tr>
													
													<tr id="clash_ipv6" style="height: 30px;" >
														<th>IPv6代理 <a class="hintstyle" href="javascript:void(0);" onclick="openmcHint(24)"><em style="color: gold;">【说明】</em></a></th>
															<td colspan="2">
																<div class="switch_field" style="display:table-cell;float: left;">
																<label for="merlinclash_ipv6switch">
																	<input id="merlinclash_ipv6switch" type="checkbox" name="ipv6" class="switch" style="display: none;">
																	<div class="switch_container" >
																		<div class="switch_bar"></div>
																		<div class="switch_circle transition_style">
																			<div></div>
																		</div>
																	</div>
																</label>
																</div>
																<div style="line-height: 30px;"><p>需要运行在TPROXY-TCP或TPROXY-TCP&UDP模式下</p>
																</div>
															</td>
													</tr>
												</table>
											</div>
											<!--KCP加速-->
											<div id="clash_kcp_area">
												<table style="margin:10px 0px 0px 0px;" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable" id="merlinclash_switch_table">
													<thead>
													<tr>
														<td colspan="2">KCP加速 -- 需要服务器端支持  <a class="hintstyle" href="javascript:void(0);" onclick="openmcHint(5)"><em>【帮助】</em></a> <a href="https://github.com/xtaci/kcptun/releases" target="_blank"><em style="color:gold;">【二进制下载】</em></a> </td>
													</tr>
													</thead>
													<tr>
														<th>KCP开关</th>
															<td colspan="2">
																<div class="switch_field" style="display:table-cell;float: left;">
																	<label for="merlinclash_kcpswitch">
																		<input id="merlinclash_kcpswitch" class="switch" type="checkbox" style="display: none;">
																		<div class="switch_container" >
																			<div class="switch_bar"></div>
																			<div class="switch_circle transition_style">
																				<div></div>
																			</div>
																		</div>
																	</label>
																</div>																	
															</td>
														</tr>
												</table>
												<div id="merlinclash_kcp_table">
												</div>
											</div>	
											
										</div>
										<!--网易云解锁-->
										<div id="tablet_8" style="display: none;">
											<div id="merlinclash-unblockneteasemusic" style="margin:-1px 0px 0px 0px;">
												<table style="margin:-1px 0px 0px 0px;" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable" >																							
													<thead>
														<tr>
															<td colspan="2">设置</td>
														</tr>
														</thead>
														<tr>
															<th >本地解锁开关</th>
															<td colspan="2">
																<div class="switch_field" style="display:table-cell;float: left;">
																	<label for="merlinclash_unblockmusic_enable">
																		<input id="merlinclash_unblockmusic_enable" class="switch" type="checkbox" style="display: none;">
																		<div class="switch_container">
																			<div class="switch_bar"></div>
																			<div class="switch_circle transition_style">
																				<div></div>
																			</div>
																		</div>
																	</label>
																</div>
															</td>
														</tr>
														<tr>
															<th >插件版本</th>
															<td colspan="2"  id="merlinclash_unblockmusic_version">
															</td>
														</tr>
														<tr>
															<th >状态</th>
															<td colspan="2"  id="merlinclash_unblockmusic_status">
															</td>
														</tr>
														<tr id="merlinclash_unblockmusic_musicapptype_tr">
															<th>
																<label >音源</label>
															</th>
															<td>
																<div style="float:left; width:165px; height:25px">
																	<select id="merlinclash_unblockmusic_musicapptype" name="merlinclash_unblockmusic_musicapptype" style="width:164px;margin:0px 0px 0px 2px;" class="input_option">
																		<option value="default" >Default</option>
																		<option value="netease" >Netease</option>
																		<option value="qq" >QQ</option>
																		<option value="baidu" >Baidu</option>
																		<option value="kugou" >Kugou</option>
																		<option value="kuwo" >Kuwo</option>
																		<option value="migu" >Migu</option>
																		<option value="joox" >Joox</option>
																	</select>
																</div>
															</td>
														</tr>
														<tr id="merlinclash_unblockmusic_endpoint_tr">
															<th>
																<label >Endpoint</label>
															</th>
															<td>
																<input type="text" id="merlinclash_unblockmusic_endpoint" name="merlinclash_unblockmusic_endpoint" class="input_15_table" style="width:200px;" value="https://music.163.com" />
															</td>
														</tr>
														<tr id="unblock_plan">
															<th>解锁方案</th>
																<td colspan="2">
																	<label for="merlinclash_unblockmusic_unblockplan">
																		<input id="merlinclash_unblockmusic_unblockplan" type="radio" name="unblockplan" value="old" checked="checked">旧版&nbsp;&nbsp;&nbsp;&nbsp;
																		<input id="merlinclash_unblockmusic_unblockplan" type="radio" name="unblockplan" value="new">新版
																	</label>	
																	<p style="color:#FC0">1.默认为旧版。不支持安卓网易云音乐8.2版本！！！</p>
																	<p style="color:#FC0">2.旧版解锁失效可尝试新版。</p>
																	<p style="color:#FC0">3.新版支持8.2版本，但会导致部分网站访问异常。</p>
																</td>
														</tr>
														<tr id="merlinclash_unblockmusic_bestquality_tr">
															<th>
																<label >强制音质优先</label>
															</th>
															<td>
																<label for="merlinclash_unblockmusic_bestquality">
																	<input id="merlinclash_unblockmusic_bestquality" type="checkbox" name="unblockmusic_bestquality">
																</label>
															</td>
														</tr>
														<tr id="merlinclash_unblockmusic_log_tr">
															<th>
																<label >开启日志</label>
															</th>
															<td>
																<label for="merlinclash_unblockmusic_log">
																	<input id="merlinclash_unblockmusic_log" type="checkbox" name="unblockmusic_log">
																</label>
																<a type="button" class="ss_btn" style="vertical-align: middle; cursor:pointer" onclick="get_unblockmusic_log()" href="javascript:void(0);">&nbsp;&nbsp;查看日志&nbsp;&nbsp;</a>
																
															</td>
														</tr>
														<tr id="merlinclash_unblockmusic_vip_tr">
															<th>
																<label >开启安卓手机版权&VIP解锁</label>
															</th>
															<td>
																<label for="merlinclash_unblockmusic_vip">
																	<input id="merlinclash_unblockmusic_vip" type="checkbox" name="unblockmusic_vip">
																</label>
																<label><em style="color: gold;">【不开，安卓客户端需设置WIFI代理解锁，开了，可能影响部分网站浏览】</em></label>
															</td>
														</tr>
														<tr id="merlinclash_unblockmusic_platforms_numbers_tr">
															<th>
																<label >音源最大搜索结果(需0.2.5版本以上)</label>
															</th>
															<td>
																<input onkeyup="this.value=this.value.replace(/[^0-3]+/,'0')" maxlength="1" id="merlinclash_unblockmusic_platforms_numbers" class="input_15_table" type="text" name="unblockmusic_platforms_numbers" value="0">
															</td>
														</tr>
														<tr id="cert_download_tr">
															<th>
																<label >证书下载</label>&nbsp;&nbsp;<a class="hintstyle" href="javascript:void(0);" onclick="openmcHint(8)"><em style="color: gold;">【证书相关】</em></a>																
															</th>
															<td>
																<input  type="button" id="merlinclash_unblockmusic_create_cert" class="ss_btn" style="vertical-align: middle; cursor:pointer;" onclick="createcert(9);" value="生成证书" />															
																<input  type="button" id="merlinclash_unblockmusic_download_cert" class="ss_btn" style="vertical-align: middle; cursor:pointer;" onclick="downloadcert();" value="下载证书" />
																
															</td>
														</tr>
														<tr id="unblockneteasemusic_restart_tr">
															<th>
																<label >重启进程</label>
															</th>
															<td>
																<input  type="button" id="merlinclash_unblockmusic_restart" class="ss_btn" style="width: 100px; vertical-align: middle; cursor:pointer;" onclick="unblock_restart();" value="重启解锁进程" />
															</td>
														</tr>	
														<tr id="unblockneteasemusic_restart_job_tr">
															<th>
																<label >网易云解锁定时重启</label>
															</th>
															<td>
																<select name="select_job" id="merlinclash_select_job" onChange="show_job()"  class="input_option" >
																	<option value="1" selected>关闭</option>
																	<option value="2">每天</option>
																	<option value="3">每周</option>
																	<option value="4">每月</option>
																</select>
																<select name="select_day" id="merlinclash_select_day" class="input_option" ></select>
																<select name="select_week" id="merlinclash_select_week" class="input_option" ></select>
																<select name="select_hour"  id="merlinclash_select_hour" class="input_option" ></select>
																<select name="select_minute"  id="merlinclash_select_minute" class="input_option" ></select>
																<input  type="button" id="merlinclash_job_save" class="ss_btn" style="vertical-align: middle; cursor:pointer;" onclick="unblock_restartjob_save();" value="保存设置" />
															</td>
														</tr>	
														<tr>
															<th>二进制下载</th>
																<td colspan="2">
																	
																	<a type="button" class="ss_btn" target="_blank" href="https://github.com/flyhigherpi/merlinclash_clash_binary/tree/master/UnblockNeteaseMusic_binary">二进制下载</a>
																</td>		
														</tr>
														<tr>
															<th>二进制上传</th>
																<td colspan="2">
																	<div class="SimpleNote" style="display:table-cell;float: left; height: 110px; line-height: 110px; margin:-40px 0;">
																		<input type="file" id="unblockmusicbinary" size="50" name="file"/>
																		<span id="unblockmusicbinary_upload" style="display:none;">完成</span>															
																		<a type="button" style="vertical-align: middle; cursor:pointer;" id="unblockmusicbinary-btn-upload" class="ss_btn" onclick="upload_unblockmusicbinary()" >上传二进制</a>
																	</div>
																</td>		
														</tr>																			
												</table>
												<div id="merlinclash_unblockmusicacl_table_div">
													<table style="margin:10px 0px 0px 0px;" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable">
														<thead>
															<tr>
																<td colspan="6">访问控制</td>
															</tr>
														</thead>
												</table>
												<div id="merlinclash_UNMACL_table" style="margin:-1px 0px 0px 0px;">
												</div>
												</div>
												<div id="UBM_note" style="margin:10px 0 0 5px"><i></i><em style="color: gold;">&nbsp;&nbsp;&nbsp;本模块采用 <a href="https://github.com/cnsilvan/UnblockNeteaseMusic" target="_blank"><em><u>Cnsilvan</em></u></a>编译的Golong版本的UnblockNeteaseMusic，实现解锁网易云音乐变灰歌曲，并通过iptabels实现透明代理解锁。<br>1.开启后，基本能实现设备联网即解锁，无需手动设置代理。<br>2.相对于之前解锁方式，本地解锁更加安全快速。<br>
												3.苹果设备经过测试均可正常解锁，如未成功解锁请按照证书<em>【安装说明】</em>操作。<br>4.如果发现解锁失败，请尝试：<br>&nbsp;&nbsp;&nbsp;a)重启解锁进程，查看设备是否解锁；<br>&nbsp;&nbsp;&nbsp;b)若重启仍无法解锁，可在APP/客户端里设置如下代理：<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;HTTP代理IP:<% nvram_get("lan_ipaddr"); %>，端口:5200<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;HTTPS代理IP:<% nvram_get("lan_ipaddr"); %>，端口:5300</div>
												
											</div>	
										</div>
										<!--附加功能-->
										<div id="tablet_4" style="display: none;">
											<div id="merlinclash-content-additional" style="margin:-1px 0px 0px 0px;">
												
												<table style="margin:-1px 0px 0px 0px;" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable" id="merlinclash_switch_table">
													<thead>
													<tr>
                                                    	<td colspan="2">功能显示开关</td>
													</tr>
													</thead>
													<tr style="height: 30px;">
														<th>标签页</th>
														<td colspan="2">
															<div style="display:table-cell;float: left;text-align: center;text-align: center;line-height: 30px;">【自定规则】</div>
															<div class="switch_field" style="display:table-cell;float: left;">
																<label for="merlinclash_check_aclrule">
																	<input id="merlinclash_check_aclrule" class="switch" type="checkbox" style="display: none;" name="aclrule_check" onchange="functioncheck('merlinclash_check_aclrule')">
																	<div class="switch_container" >
																		<div class="switch_bar"></div>
																		<div class="switch_circle transition_style">
																			<div></div>
																		</div>
																	</div>
																</label>
															</div>
															<div style="display:table-cell;float: left;text-align: center;text-align: center;line-height: 30px;">【黑&nbsp;&nbsp;&nbsp;白&nbsp;&nbsp;&nbsp;郎&nbsp;&nbsp;&nbsp;君】</div>
															<div class="switch_field" style="display:table-cell;float: left;">
																<label for="merlinclash_check_controllist">
																	<input id="merlinclash_check_controllist" class="switch" type="checkbox" style="display: none;" name="controllist_check" onchange="functioncheck('merlinclash_check_controllist')">
																	<div class="switch_container" >
																		<div class="switch_bar"></div>
																		<div class="switch_circle transition_style">
																			<div></div>
																		</div>
																	</div>
																</label>
															</div>
															<div style="display:table-cell;float: left;text-align: center;text-align: center;line-height: 30px;">【云&nbsp;&nbsp;村&nbsp;&nbsp;解&nbsp;&nbsp;锁】</div>
															<div class="switch_field" style="display:table-cell;float: left;">
																<label for="merlinclash_check_unblock">
																	<input id="merlinclash_check_unblock" class="switch" type="checkbox" style="display: none;" name="unblock_check" onchange="functioncheck('merlinclash_check_unblock')">
																	<div class="switch_container" >
																		<div class="switch_bar"></div>
																		<div class="switch_circle transition_style">
																			<div></div>
																		</div>
																	</div>
																</label>
															</div>
															<div style="display:table-cell;float: left;text-align: center;text-align: center;line-height: 30px;">【护网大师】</div>
															<div class="switch_field" style="display:table-cell;float: left;">
																<label for="merlinclash_check_kp">
																	<input id="merlinclash_check_kp" class="switch" type="checkbox" style="display: none;" name="kp_check" onchange="functioncheck('merlinclash_check_kp')">
																	<div class="switch_container" >
																		<div class="switch_bar"></div>
																		<div class="switch_circle transition_style">
																			<div></div>
																		</div>
																	</div>
																</label>
															</div>
															<div style="display:table-cell;float: left;text-align: center;text-align: center;line-height: 30px;">【DlerCloud登陆】</div>
															<div class="switch_field" style="display:table-cell;float: left;">
																<label for="merlinclash_check_dlercloud">
																	<input id="merlinclash_check_dlercloud" class="switch" type="checkbox" style="display: none;" name="dlercloud_check" onchange="functioncheck('merlinclash_check_dlercloud')">
																	<div class="switch_container" >
																		<div class="switch_bar"></div>
																		<div class="switch_circle transition_style">
																			<div></div>
																		</div>
																	</div>
																</label>
															</div>
														</td>	
													</tr>
													<tr style="height: 30px;">
														<th>配置文件</th>
															<td colspan="2">
																<div style="display:table-cell;float: left;text-align: center;text-align: center;line-height: 30px;">【导入&nbsp;clash】</div>
																<div class="switch_field" style="display:table-cell;float: left;">
																	<label for="merlinclash_check_clashimport">
																	<input id="merlinclash_check_clashimport" class="switch" type="checkbox" style="display: none;" name="clashimport_check" onchange="functioncheck('merlinclash_check_clashimport')">
																	<div class="switch_container" >
																		<div class="switch_bar"></div>
																		<div class="switch_circle transition_style">
																			<div></div>
																		</div>
																	</div>
																</label>
																</div>
																<div style="display:table-cell;float: left;text-align: center;text-align: center;line-height: 30px;">【小白一键订阅】</div>
																<div class="switch_field" style="display:table-cell;float: left;">
																	<label for="merlinclash_check_xiaobai">
																		<input id="merlinclash_check_xiaobai" class="switch" type="checkbox" style="display: none;" name="xiaobai_check" onchange="functioncheck('merlinclash_check_xiaobai')">
																		<div class="switch_container" >
																			<div class="switch_bar"></div>
																			<div class="switch_circle transition_style">
																				<div></div>
																			</div>
																		</div>
																	</label>
																</div>
																<div style="display:table-cell;float: left;text-align: center;text-align: center;line-height: 30px;"><p id="scoracl3"></p></div>
																<div class="switch_field" style="display:table-cell;float: left;">
																	<label for="merlinclash_check_sclocal">
																		<input id="merlinclash_check_sclocal" class="switch" type="checkbox" style="display: none;" name="sclocal_check" onchange="functioncheck('merlinclash_check_sclocal')">
																		<div class="switch_container" >
																			<div class="switch_bar"></div>
																			<div class="switch_circle transition_style">
																				<div></div>
																			</div>
																		</div>
																	</label>
																</div>
																<div style="display:table-cell;float: left;text-align: center;text-align: center;line-height: 30px;">【yaml&nbsp;下&nbsp;载】</div>
																<div class="switch_field" style="display:table-cell;float: left;">
																	<label for="merlinclash_check_yamldown">
																		<input id="merlinclash_check_yamldown" class="switch" type="checkbox" style="display: none;" name="yamldown_check" onchange="functioncheck('merlinclash_check_yamldown')">
																		<div class="switch_container" >
																			<div class="switch_bar"></div>
																			<div class="switch_circle transition_style">
																				<div></div>
																			</div>
																		</div>
																	</label>
																</div>
																<div style="display:table-cell;float: left;text-align: center;text-align: center;line-height: 30px;">【导入科学节点】</div>
																<div class="switch_field" style="display:table-cell;float: left;">
																	<label for="merlinclash_check_ssimport">
																		<input id="merlinclash_check_ssimport" class="switch" type="checkbox" style="display: none;" name="ssimport_check" onchange="functioncheck('merlinclash_check_ssimport')">
																		<div class="switch_container" >
																			<div class="switch_bar"></div>
																			<div class="switch_circle transition_style">
																				<div></div>
																			</div>
																		</div>
																	</label>
																</div>
																<div id="upcusrule" style="display:table-cell;float: left;text-align: center;text-align: center;line-height: 30px;">【上传自定订阅】</div>
																<div id="upcusrulecbox" class="switch_field" style="display:table-cell;float: left;">
																	<label for="merlinclash_check_upcusrule">
																		<input id="merlinclash_check_upcusrule" class="switch" type="checkbox" style="display: none;" name="upcusrule_check" onchange="functioncheck('merlinclash_check_upcusrule')">
																		<div class="switch_container" >
																			<div class="switch_bar"></div>
																			<div class="switch_circle transition_style">
																				<div></div>
																			</div>
																		</div>
																	</label>
																</div>
															</td>
															
													</tr>
													<tr style="height: 30px;">
														<th>自定规则</th>
															<td colspan="2">
																<div style="display:table-cell;float: left;text-align: center;text-align: center;line-height: 30px;">【Script&nbsp;编辑】</div>
																<div class="switch_field" style="display:table-cell;float: left;">
																	<label for="merlinclash_check_scriptedit">
																	<input id="merlinclash_check_scriptedit" class="switch" type="checkbox" style="display: none;" name="scriptedit_check" onchange="functioncheck('merlinclash_check_scriptedit')">
																	<div class="switch_container" >
																		<div class="switch_bar"></div>
																		<div class="switch_circle transition_style">
																			<div></div>
																		</div>
																	</div>
																</label>
																</div>
															</td>
															
													</tr>
													<tr style="height: 30px;">
														<th>附加功能</th>
															<td colspan="2">
																<div style="display:table-cell;float: left;text-align: center;text-align: center;line-height: 30px;">【dns编辑区】</div>
																<div class="switch_field" style="display:table-cell;float: left;">
																	<label for="merlinclash_check_cdns">
																	<input id="merlinclash_check_cdns" class="switch" type="checkbox" style="display: none;" name="cdns_check" onchange="functioncheck('merlinclash_check_cdns')">
																	<div class="switch_container" >
																		<div class="switch_bar"></div>
																		<div class="switch_circle transition_style">
																			<div></div>
																		</div>
																	</div>
																</label>
																</div>
																<div style="display:table-cell;float: left;text-align: center;text-align: center;line-height: 30px;">【host&nbsp;&nbsp;编辑区】</div>
																<div class="switch_field" style="display:table-cell;float: left;">
																	<label for="merlinclash_check_chost">
																		<input id="merlinclash_check_chost" class="switch" type="checkbox" style="display: none;" name="cdns_check" onchange="functioncheck('merlinclash_check_chost')">
																		<div class="switch_container" >
																			<div class="switch_bar"></div>
																			<div class="switch_circle transition_style">
																				<div></div>
																			</div>
																		</div>
																	</label>
																</div>
															</td>
															
													</tr>
													<tr style="height: 30px;">
														<th>高级模式</th>
															<td colspan="2">
																<div style="display:table-cell;float: left;text-align: center;text-align: center;line-height: 30px;">【透明代理】</div>
																<div class="switch_field" style="display:table-cell;float: left;">
																<label for="merlinclash_check_noipt">
																	<input id="merlinclash_check_noipt" class="switch" type="checkbox" style="display: none;" name="noipt_check" onchange="functioncheck('merlinclash_check_noipt')">
																	<div class="switch_container" >
																		<div class="switch_bar"></div>
																		<div class="switch_circle transition_style">
																			<div></div>
																		</div>
																	</div>
																</label>
																</div>
																<div style="display:table-cell;float: left;text-align: center;text-align: center;line-height: 30px;">【自&nbsp;定&nbsp;义&nbsp;端&nbsp;口】</div>
																<div class="switch_field" style="display:table-cell;float: left;">
																<label for="merlinclash_check_cusport">
																	<input id="merlinclash_check_cusport" class="switch" type="checkbox" style="display: none;" name="cusport_check" onchange="functioncheck('merlinclash_check_cusport')">
																	<div class="switch_container" >
																		<div class="switch_bar"></div>
																		<div class="switch_circle transition_style">
																			<div></div>
																		</div>
																	</div>
																</label>
																</div>
																<div id="tproxy_show" style="display:table-cell;float: left;text-align: center;text-align: center;line-height: 30px;">【TPROXY】</div>
																<div id="tproxy_showcbox" class="switch_field" style="display:table-cell;float: left;">
																<label for="merlinclash_check_tproxy">
																	<input id="merlinclash_check_tproxy" class="switch" type="checkbox" style="display: none;" name="tproxy_check" onchange="functioncheck('merlinclash_check_tproxy')">
																	<div class="switch_container" >
																		<div class="switch_bar"></div>
																		<div class="switch_circle transition_style">
																			<div></div>
																		</div>
																	</div>
																</label>
																</div>
																<div style="display:table-cell;float: left;text-align: center;text-align: center;line-height: 30px;">【KCP加速】</div>
																<div class="switch_field" style="display:table-cell;float: left;">
																<label for="merlinclash_check_kcp">
																	<input id="merlinclash_check_kcp" class="switch" type="checkbox" style="display: none;" name="kcp_check" onchange="functioncheck('merlinclash_check_kcp')">
																	<div class="switch_container" >
																		<div class="switch_bar"></div>
																		<div class="switch_circle transition_style">
																			<div></div>
																		</div>
																	</div>
																</label>
																</div>	
															</td>
													</tr>
												</table>
												<table style="margin:10px 0px 0px 0px;" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable" id="merlinclash_switch_table">
													<thead>
													<tr>
														<td colspan="2">备份&还原 <a class="hintstyle" href="javascript:void(0);" onclick="openmcHint(22)"><em style="color:gold">【备份内容说明】</em></a></td>
													</tr>
													</thead>
													<tr>
														<th id="btn-open-clash-dashboard" class="btn btn-primary">一键备份</th>
														<td colspan="2">
															<a type="button" style="vertical-align: middle; cursor:pointer;" id="clashdata-btn-download" class="ss_btn" onclick="down_clashdata(1)" >下载备份</a>
														</td>
													</tr>
													<tr>
													<th id="btn-open-clash-dashboard" class="btn btn-primary">一键还原</th>
													<td colspan="2">
														<div class="SimpleNote" style="display:table-cell;float: left; height: 110px; line-height: 110px; margin:-40px 0;">
															<input type="file" style="width: 200px;margin: 0,0,0,0px;" id="clashdata" size="50" name="file"/>
															<span id="clashdata_info" style="display:none;">完成</span>															
															<a type="button" style="vertical-align: middle; cursor:pointer;" id="clashdata-btn-upload" class="ss_btn" onclick="upload_clashdata()" >恢复备份</a>
														</div>
													</td>
													</tr>
												</table>
												<table style="margin:10px 0px 0px 0px;" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable" id="merlinclash_switch_table">
													<thead>
													<tr>
														<td colspan="2">更新管理</td>
													</tr>
													</thead>
													<tr>
													<th><a class="hintstyle" href="javascript:void(0);" onclick="openmcHint(21)">GeoIP 数据库</a></th>
														<td colspan="2">
															<div class="SimpleNote" id="head_illustrate">
																<p>在线更新 Clash 使用的GeoIP数据库</p>
																<p style="color:#FC0">注：更新不会对比新旧版本号，重复点击会重复升级！（1个月左右更新一次即可）</p>
																<p>&nbsp;</p>
																<select id="merlinclash_geoip_type" style="width:120px;margin:0px 0px 0px 2px;text-align:left;padding-left: 0px;" class="input_option">
																	<option value="maxmind">MaxMind-4M版</option>
																	<option value="ipip">ipip-4M版</option>
																	<option value="Hackl0us">Hackl0us-100kb版</option>	
																	<option value="Loyalsoldier">Loyalsoldier增强版</option>					
																</select>
																<a type="button" class="ss_btn" style="cursor:pointer" onclick="geoip_update(5)">更新GeoIP数据库</a>
																<span id="geoip_updata_date">上次更新时间：</span>
																</div>
														</td>		
													</tr>
													<tr>
													<th>大陆IP白名单</th>
														<td colspan="2">
															<div class="SimpleNote" id="head_illustrate">
																<p>大陆IP白名单 使用由 <a href="https://github.com/DivineEngine" target="_blank"><u>DivineEngine</u></a> 提供的 <a href="https://github.com/DivineEngine/Profiles/blob/master/Clash/RuleSet/Extra/ChinaIP.yaml" target="_blank"><u>ChinaIP</u></a>白名单规则</p>
																<p style="color:#FC0">注：更新不会对比新旧版本号，重复点击会重复升级！（1个月左右更新一次即可）</p>
																<p>&nbsp;</p>
																<a type="button" class="ss_btn" style="cursor:pointer" onclick="chnroute_update(25)">更新大陆白名单规则</a>
																<span id="chnroute_updata_date">上次更新时间：</span>
																</div>
														</td>		
													</tr>
													<tr>
														<th>Clash二进制替换 --在线更换</th>
															<td colspan="2">
																<div class="SimpleNote" id="head_illustrate">
																	<select id="merlinclash_clashbinarysel"  name="clashbinarysel" dataType="Notnull" class="input_option" style="width: 200px;"></select>
																	<a type="button" class="ss_btn" style="cursor:pointer" onclick="clash_getversion(10)">获取远程版本文件</a>		
																	<a type="button" class="ss_btn" style="cursor:pointer" onclick="clash_replace(11)">替换clash二进制</a>																	
																</div>
															</td>		
													</tr>
													<tr>
														<th>Clash二进制替换 --本地替换</th>
															<td colspan="2">
																<div class="SimpleNote" style="display:table-cell;float: left; height: 110px; line-height: 110px; margin:-40px 0;">
																	<input type="file" id="clashbinary" size="50" name="file"/>
																	<span id="clashbinary_upload" style="display:none;">完成</span>															
																	<a type="button" style="vertical-align: middle; cursor:pointer;" id="clashbinary-btn-upload" class="ss_btn" onclick="upload_clashbinary()" >上传clash二进制</a>
																</div>
															</td>		
													</tr>
													<!--<tr>
														<th>内置【常规规则】更新</th>
															<td colspan="2">
																<div class="SimpleNote" id="head_illustrate">																	
																	<a type="button" id="updatecomBtn" class="ss_btn" style="cursor:pointer" onclick="proxygroup_update(14)">&nbsp;&nbsp;更新常规规则&nbsp;&nbsp;</a>
																	<span id="proxygroup_version">&nbsp;&nbsp;当前版本：</span>
																	
																</div>
															</td>		
													</tr>-->
													<tr id="up_scrule">
														<th>SubConverter&nbsp;&nbsp;规则更新</th>
															<td colspan="2">
																<div class="SimpleNote" id="head_illustrate">																	
																	<a type="button" id="updatescBtn" class="ss_btn" style="cursor:pointer" onclick="sc_update(18)">&nbsp;&nbsp;更新S--C规则&nbsp;&nbsp;</a>
																	<span id="sc_version">&nbsp;&nbsp;当前版本：</span>
																	
																</div>
															</td>		
													</tr>
												</table>
												<div id="clash_dns_area">										
													<table style="margin:10px 0px 0px 0px;" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable" id="merlinclash_dnsfiles_table">
														<thead>
														<tr>
															<td colspan="2">DNS&nbsp;&nbsp;编辑 -- <em style="color: gold;">【不懂勿动！编辑完成后需点击“修改提交”保存配置，下次启动Merlin Clash时生效】|【开启编辑：<input id="merlinclash_dnsedit_check" class="barcodeSavePrint" type="checkbox" name="dnsedit_check" >】</em></td>
														</tr>
														<script>
															$(function () {
																$(".barcodeSavePrint").click(function () {
																	if (this.checked==true){
																		document.getElementById("merlinclash_dns_edit_content1").readOnly = false

																	}else{
																		document.getElementById("merlinclash_dns_edit_content1").readOnly = true
																	}
																})
															})
														</script>
														</thead>
													</table>
													<table style="margin:-1px 0px 0px 0px;" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable" id="merlinclash_dnsfiles_content_table">
															<tr id="dns_plan_edit">
																<th>DNS内容编辑</th>
																	<td colspan="2">
																		<label for="merlinclash_dnsplan_edit">
																			<input id="merlinclash_dnsplan_edit" type="radio" name="dnsplan_edit" value="redirhost" checked="checked">Redir-Host
																			<input id="merlinclash_dnsplan_edit" type="radio" name="dnsplan_edit" value="fakeip">Fake-ip
																			<input class="ss_btn" type="button" onclick="dnsfilechange()" value="修改提交">
																		</label>
																		<script>
																			$("[name='dnsplan_edit']").on("change",
																			function (e) {
																				var dns_tag=$(e.target).val();
																				get_dnsyaml(dns_tag);
																			}
																			);
																		</script>	
																	</td>
															</tr>
													</table>
													<table style="margin:-1px 0px 0px 0px;" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable">
														<div id="merlinclash_dns_edit_content" style="margin-top:-1px;overflow:hidden;">
															<textarea rows="7" wrap="on" id="merlinclash_dns_edit_content1" name="dns_edit_content1" style="margin: 0px; width: 709px; height: 300px; resize: none;" readonly="true"></textarea>
														</div>
														
													</table>
												</div>	
												<div id="clash_host_area">	
													<!--自定义HOST-->
													<table style="margin:10px 0px 0px 0px;" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable">
														<thead>
															<tr>
																<td colspan="2">自定义&nbsp;&nbsp;HOST&nbsp;&nbsp;<a class="hintstyle" href="javascript:void(0);" onclick="openmcHint(11)"><em>【说明】</a></em>&nbsp;<em style="color:gold;">|【开启编辑：<input id="merlinclash_hostedit_check" class="hostenableedit" type="checkbox" name="hostedit_check" >】</em></td>
															</tr>
														</thead>
															<script>
																$(function () {
																	$(".hostenableedit").click(function () {
																		if (this.checked==true){
																			document.getElementById("merlinclash_host_content1").readOnly = false
		
																		}else{
																			document.getElementById("merlinclash_host_content1").readOnly = true
																		}
																	})
																})
															</script>
															<tr id="hostselect">
																<th>HOST文件选择</th>
																	<td colspan="2">
																		<select id="merlinclash_hostsel"  name="hostsel" dataType="Notnull" msg="HOST文件不能为空!" class="input_option" ></select>
																		<a type="button" style="vertical-align: middle;" class="ss_btn" style="cursor:pointer" onclick="hostchange()" href="javascript:void(0);" >&nbsp;&nbsp;修改提交&nbsp;&nbsp;</a>
																		<a type="button" style="vertical-align: middle;" class="ss_btn" style="cursor:pointer" onclick="download_host()" href="javascript:void(0);">&nbsp;&nbsp;下载HOST&nbsp;&nbsp;</a>
																		<a type="button" style="vertical-align: middle;" class="ss_btn" style="cursor:pointer" onclick="del_host_sel()" href="javascript:void(0);" >&nbsp;&nbsp;删除HOST&nbsp;&nbsp;</a>
																	</td>
																	<script>
																		$("[name='hostsel']").on("change",
																		function (e) {
																			var host_tag=$(e.target).val();
																			get_host(host_tag);
																		}
																		);
																	</script>
															</tr>
														
													</table>
												
													<table style="margin:-1px 0px 0px 0px;" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable">
														<div id="merlinclash_host_content" style="margin-top:-1px;overflow:hidden;">
															<textarea rows="7" wrap="on" id="merlinclash_host_content1" style="margin: 0px; width: 709px; height: 300px; resize: none; " readonly="true"></textarea>
														</div>
														<tr>
															<th>上传HOST文件</th>
															<td colspan="2">
																<div class="SimpleNote" style="display:table-cell;float: left; height: 110px; line-height: 110px; margin:-40px 0;">
																	<input type="file" id="clashhost" size="50" name="file"/>
																	<span id="clashhost_upload" style="display:none;">完成</span>															
																	<a type="button" style="vertical-align: middle; cursor:pointer;" id="clashhost-btn-upload" class="ss_btn" onclick="upload_clashhost()" >上传HOST文件</a>
																	
																</div>
															</td>		
														</tr>
													</table>
												</div>
											</div>
										</div>
										<!--KOOLPROXY-->
										<div id="tablet_5" style="display: none;">
											<div id="merlinclash-koolproxyL" style="margin:-1px 0px 0px 0px;">
												<div id="basic_settings" style="margin:-1px 0px 0px 0px;">
													<table style="margin:-1px 0px 0px 0px;" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable" >																							
														<thead>
															<tr>
																<td colspan="2">基础设置</td>
															</tr>
															</thead>
															<tr id="switch_tr">
																<th >KOOLPROXY开关</th>
																<td colspan="2">
																	<div class="switch_field" style="display:table-cell;float: left;">
																		<label for="merlinclash_koolproxy_enable">
																			<input id="merlinclash_koolproxy_enable" class="switch" type="checkbox" style="display: none;">
																			<div class="switch_container">
																				<div class="switch_bar"></div>
																				<div class="switch_circle transition_style">
																					<div></div>
																				</div>
																			</div>
																		</label>
																	</div>
																</td>
															</tr>
															<tr id="kp_status">
																<th >运行状态</th>
																<td colspan="2"  id="merlinclash_koolproxy_status">
																</td>
															</tr>
														<tr id="policy_tr">
															<th>选择过滤模式</th>
															<td>
																<select name="merlinclash_koolproxy_mode" id="merlinclash_koolproxy_mode" class="input_option" onchange="update_visibility(this);" style="width:auto;margin:0px 0px 0px 2px;">
																	<option value="1" selected>全局模式</option>
																	<option value="2">ipset模式</option>
																	<option value="3">视频模式（旧-兼容）</option>
																</select>
															</td>
														</tr>
														<tr id="auto_reboot_switch">
															<th>插件自动重启</th>
															<td>
																<select name="merlinclash_koolproxy_reboot" id="merlinclash_koolproxy_reboot" class="input_option" style="width:auto;margin:0px 0px 0px 2px;" onchange="update_visibility();">
																	<option value="1">定时</option>
																	<option value="2">间隔</option>
																	<option value="0" selected>关闭</option>
																</select>
																<span id="merlinclash_koolproxy_reboot_hour_span">
																	&nbsp;&nbsp;&nbsp;&nbsp;
																	每天
																	<select id="merlinclash_koolproxy_reboot_hour" name="merlinclash_koolproxy_reboot_hour" class="ssconfig input_option" >
																	</select>
																	<select id="merlinclash_koolproxy_reboot_min" name="merlinclash_koolproxy_reboot_min" class="ssconfig input_option" >
																	</select>
																	重启
																	&nbsp;&nbsp;&nbsp;&nbsp;
																</span>
																<span id="merlinclash_koolproxy_reboot_interval_span">
																	&nbsp;&nbsp;&nbsp;&nbsp;
																	每隔
																	<select id="merlinclash_koolproxy_reboot_inter_hour" name="merlinclash_koolproxy_reboot_inter_hour" class="ssconfig input_option" >
																	</select>
																	<select id="merlinclash_koolproxy_reboot_inter_min" name="merlinclash_koolproxy_reboot_inter_min" class="ssconfig input_option" >
																	</select>
																	重启koolproxy
																	&nbsp;&nbsp;&nbsp;&nbsp;
																</span>
															</td>
														</tr>
														<tr id="acl_method_tr">
															<th>访问控制匹配方法</th>
															<td>
																<select name="merlinclash_koolproxy_acl_method" id="merlinclash_koolproxy_acl_method" class="input_option" style="width:127px;margin:0px 0px 0px 2px;" onchange="update_visibility();">
																	<option value="1" selected>IP + MAC匹配</option>
																	<option value="2">仅IP匹配</option>
																	<option value="3">仅MAC匹配</option>
																</select>
															</td>
														</tr>
														<tr id="no_china_ip_route">
															<th>外网IP绕过KP</th>
																<td colspan="2">
																	<div class="switch_field" style="display:table-cell;float: left;">
																	<label for="merlinclash_passkpswitch">
																		<input id="merlinclash_passkpswitch" type="checkbox" name="cir" class="switch" style="display: none;">
																		<div class="switch_container" >
																			<div class="switch_bar"></div>
																			<div class="switch_circle transition_style">
																				<div></div>
																			</div>
																		</div>
																	</label>
																	
																</div>
																</td>
														</tr>
														<tr id="kpcert_download_tr">
															<th width="35%">证书下载（用于https过滤）</th>
															<td>
																<input type="button" id="merlinclash_koolproxy_download_cert" class="ss_btn" style="cursor:pointer" value="证书下载">
															</td>
														</tr>
														<tr id="kprule_update">
															<th width="35%">规则更新</th>
																<td>
																	<div class="SimpleNote" style="display:table-cell;float: left; height: 110px; line-height: 110px; margin:-40px 0;">
																		<input type="file" id="koolproxyrule" size="50" name="file"/>
																		<span id="koolproxyrule_upload" style="display:none;">完成</span>															
																		<a type="button" style="vertical-align: middle; cursor:pointer;" id="clashpatch-btn-upload" class="ss_btn" onclick="upload_kprule()" >上传规则包</a>
																	</div>
																</td>		
														</tr>
														<tr id="klloproxy_com">
															<th width="35%">KP交流</th>
															<td>
																<a type="button" class="ss_btn" target="_blank" href="https://t.me/joinchat/AAAAAD-tO7GPvfOU131_vg">加入电报群</a>
															</td>
														</tr>
													</table>
												</div>
												<div id="rule_table_div" style="margin:10px 0px 0px 0px;width:748px">
													<table class="FormTable" id="rule_table" style="margin:-1px 0px 0px 0px;border: 1px solid #000000;width:100%;" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" >
														<thead>
															<tr>
																<td colspan="7">规则控制 &nbsp;&nbsp;<a class="hintstyle" href="javascript:void(0);" onclick="openmcHint(19)"><font color="#ffcc00"><u>[说明]</u></font></a></td>
															</tr>
														</thead>
														<tr>
															<th style="width:30px;text-align:center;">启用</th>
															<th style="width:70px;">文件</th>
															<th style="width:250px;">地址</th>
															<th style="width:40px;text-align:center;">别名</th>
															<th style="width:150px;">备注</th>
															<th style="width:30px;text-align:center;">编辑</th>
															<th style="width:30px;text-align:center;">删除</th>
														</tr>
														<tr>
															<td style="text-align:center;">
																<input type="checkbox" id="merlinclash_koolproxy_rule_enable_d1" checked="checked" name="merlinclash_koolproxy_rule_enable_d1" />
															</td>
															<td>
																koolproxy.txt
															</td>
															<td>
																https://www.kpguizemeiyoule.top/koolproxy.txt
															</td>
															<td style="text-align:center;">
																静态规则
															</td>
															<td id="kp_rule_1">
																2018-10-2 21:23 / 11799条
															</td>
															<td>
															</td>
															<td>
															</td>
														</tr>
														<tr>
															<td style="text-align:center;">
																<input type="checkbox" id="merlinclash_koolproxy_rule_enable_d2" checked="checked" name="merlinclash_koolproxy_rule_enable_d2" />
															</td>
															<td>
																daily.txt
															</td>
															<td>
																https://www.kpguizemeiyoule.top/daily.txt
															</td>
															<td style="text-align:center;">
																每日规则
															</td>
															<td id="kp_rule_2">
																107条
															</td>
															<td>
															</td>
															<td>
															</td>
															</tr>
															<tr>
															<td style="text-align:center;">
																<input type="checkbox" id="merlinclash_koolproxy_rule_enable_d3" checked="checked" name="merlinclash_koolproxy_rule_enable_d3" />
															</td>
															<td>
																kp.dat
															</td>
															<td>
																https://www.kpguizemeiyoule.top/kp.dat
															</td>
															<td style="text-align:center;">
																视频规则
															</td>
															<td id="kp_rule_3">
																2018-09-27 01:10
															</td>
															<td>
															</td>
															<td>
															</td>
														</tr>
														<tr>
															<td style="text-align:center;">
																<input type="checkbox" id="merlinclash_koolproxy_rule_enable_d4" checked="checked" name="merlinclash_koolproxy_rule_enable_d4" />
															</td>
															<td>
																user.txt
															</td>
															<td>
																https://down.cmccw.xyz/user.txt
															</td>
															<td style="text-align:center;">
																自定规则
															</td>
															<td id="kp_rule_4">
																2条
															</td>
															<td>
																<input style="margin-left: 6px;margin: -3px 0px -5px 6px;" type="button" class="edit_btn" onclick="open_user_rule()" value="" />
															</td>
															<td>
															</td>
														</tr>
														<tr>
															<td style="text-align:center;">
																<input type="checkbox" id="merlinclash_koolproxy_rule_enable" name="merlinclash_koolproxy_rule_enable" style="width:30px;"/>
															</td>
															<td>
																<input type="text" id="merlinclash_koolproxy_rule_file" name="merlinclash_koolproxy_rule_file" class="input_15_table" style="width:70px;" placeholder="" />
															</td>
															<td>
																<input type="text" id="merlinclash_koolproxy_rule_addr" name="merlinclash_koolproxy_rule_addr" class="input_15_table" style="width:250px;" placeholder="" />
															</td>
															<td>
																<input type="text" id="merlinclash_koolproxy_rule_note" name="merlinclash_koolproxy_rule_note" class="input_15_table" style="width:55px;" placeholder="" />
															</td>
															<td>
															</td>
															<td>
																<input style="margin-left: 6px;margin: -3px 0px -5px 6px;" type="button" class="add_btn" onclick="add_kpyrule_Tr()" value="" />
															</td>													
															<td>
															</td>
														</tr>
													</table>
												</div>
												<div id="merlinclash_koolproxyacl_table_div">
													<table style="margin:10px 0px 0px 0px;" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable">
														<thead>
															<tr>
																<td colspan="6">访问控制</td>
															</tr>
														</thead>
												</table>
												<div id="merlinclash_KPYACL_table" style="margin:-1px 0px 0px 0px;">
												</div>
												</div>
												<div id="KPYACL_note" style="margin-top: 5px;">
													<div><i>1.过滤https站点需要为相应设备安装证书，并启用http + https过滤！</i></div>
													<div><i>2.在路由器下的设备，不管是电脑，还是移动设备，都可以在浏览器中输入<u><font color='#66FF00'>110.110.110.110</font></u>来下载证书。</i></div>
													<div><i>3.如果想在多台装有KP的路由设备上使用一个证书，请用winscp软件备份/koolshare/koolproxy/data文件夹，并上传到另一台路由。</i></div>
													<div><i></br></i></div>
												</div>
											</div>
										</div>
										<!--当前配置-->
										<div id="tablet_6" style="display: none;">
											<div id="yaml_content" style="margin-top:0px; width:750px; height: 650px;">
												<textarea class="sbar" cols="63" rows="36" wrap="on" readonly="readonly" id="yaml_content1" style="margin: 0px; width: 709px; height: 645px; resize: none;"></textarea>
											</div>
										</div>
										<!--dlercloud-->
										<div id="tablet_10" style="display: none;">
											<div id="dlercloud_login" style="margin-top:0px; width:750px; height: 150px;">
												
                                                <table style="margin:-1px 0px 0px 0px;" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable" >
													<thead>
														<tr>
															<td colspan="2">Dler Cloud登陆</td>
														</tr>
														</thead>
													<tr id="clash_loginname">
														<th>用户名</th>
															<td>
																<div style="display:table-cell;float: left;margin-left:0px;">
																	<input id="merlinclash_dc_name" style="color: #FFFFFF; width: 300px; height: 20px; background-color:rgba(87,109,115,0.5); font-family: Arial, Helvetica, sans-serif; font-weight:normal; font-size:12px;" placeholder="">															
																														
																</div>
															</td>
                                                        </tr>
                                                        <tr id="clash_loginpasswd">
                                                            <th>密码</th>
                                                                <td>
                                                                    <div style="display:table-cell;float: left;margin-left:0px;">
                                                                        <input id="merlinclash_dc_passwd" type="password" style="color: #FFFFFF; width: 300px; height: 20px; background-color:rgba(87,109,115,0.5); font-family: Arial, Helvetica, sans-serif; font-weight:normal; font-size:12px;" placeholder="">															
                                                                                                                            
                                                                    </div>
                                                                </td>
                                                            </tr>
                                                            <tr id="clash_loginbtn">
                                                                <th>登陆</th>
                                                                    <td>
                                                                        <div style="display:table-cell;float: left;margin-left:0px;">
                                                                            <a type="button" style="vertical-align: middle; margin:-10px 10px;" class="ss_btn" style="cursor:pointer" onclick="dc_login()" href="javascript:void(0);">&nbsp;&nbsp;登陆&nbsp;&nbsp;</a>
																			&nbsp;&nbsp;
																			<a type="button" style="vertical-align: middle; margin:-10px 10px;" class="ss_btn" style="cursor:pointer" href="https://dlercloud.com/auth/login" target="_blank">&nbsp;&nbsp;官网&nbsp;&nbsp;</a>
																                                           
                                                                        </div>
                                                                    </td>
                                                                </tr>
												</table>	
                                            </div>
                                            <div id="dlercloud_content" style="margin-top:0px; width:750px; height: 650px;">
                                                <table style="margin:-1px 0px 0px 0px;" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable" >
                                                    <thead>
														<tr>
															<td colspan="2">Dler Cloud信息</td>
														</tr>
														</thead>
													<tr id="clash_loginname">
														<th>用户名</th>
															<td>
																<div style="display:table-cell;float: left;margin-left:0px;">
																	<span id="dc_name"></span>	
																	<span id="dc_token" style="display: none;"></span>															
                                                                    <a type="button" style="vertical-align: middle; margin:-10px 10px;" class="ss_btn" style="cursor:pointer" onclick="dc_logout()" href="javascript:void(0);">&nbsp;&nbsp;退出&nbsp;&nbsp;</a>  													
																</div>
															</td>
													</tr>													
                                                    <tr id="clash_money">
														<th>余额</th>
															<td>
																<div style="display:table-cell;float: left;margin-left:0px;">
																	<span id="dc_money"></span>															
                                                                    </div>
															</td>
													</tr> 
													<tr id="clash_affmoney">
														<th>返利</th>
															<td>
																<div style="display:table-cell;float: left;margin-left:0px;">
																	<span id="dc_affmoney"></span>															
                                                                    </div>
															</td>
													</tr> 
													<tr id="clash_integral">
														<th>积分</th>
															<td>
																<div style="display:table-cell;float: left;margin-left:0px;">
																	<span id="dc_integral"></span>															
                                                                    </div>
															</td>
                                                    </tr> 
                                                    <tr id="clash_plan">
														<th>当前套餐</th>
															<td>
																<div style="display:table-cell;float: left;margin-left:0px;">
																	<span id="dc_plan"></span>															
                                                                    </div>
															</td>
                                                    </tr> 
                                                    <tr id="clash_plantime">
														<th>到期时间</th>
															<td>
																<div style="display:table-cell;float: left;margin-left:0px;">
																	<span id="dc_plantime"></span>															
                                                                   </div>
															</td>
                                                    </tr> 
                                                    <tr id="clash_usedTraffic">
														<th>已用流量</th>
															<td>
																<div style="display:table-cell;float: left;margin-left:0px;">
																	<span id="dc_usedTraffic"></span>															
                                                                  	</div>
														</td>
                                                    </tr> 
                                                    <tr id="clash_unusedTraffic">
														<th>可用流量</th>
															<td>
																<div style="display:table-cell;float: left;margin-left:0px;">
																	<span id="dc_unusedTraffic"></span>															
                                                                  </div>
														</td>
													</tr>
												</table>
												<table style="margin:10px 0px 0px 0px;" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable" >
													<thead>
														<tr>
															<td colspan="2">订阅相关 -- <em style="color: gold;">如重置过连接参数，需要退出重新登陆才可以订阅</em></td>
														</tr>
													</thead>
													
                                                    <tr id="clash_ss">
														<th>SS节点</th>
															<td>
																<div style="display:table-cell;float: left;margin-left:0px;">
																	<span id="dc_ss"></span>						
                                                                    <a type="button" style="vertical-align: middle; margin:-10px 10px;" class="ss_btn" style="cursor:pointer" onclick="dc_ss_yaml(2)" href="javascript:void(0);">订阅</a>  													
																</div>
															</td>
                                                    </tr>
                                                    <tr id="clash_v2">
														<th>v2ray节点</th>
															<td>
																<div style="display:table-cell;float: left;margin-left:0px;">
																	<span id="dc_v2"></span>															
                                                                    <a type="button" style="vertical-align: middle; margin:-10px 10px;" class="ss_btn" style="cursor:pointer" onclick="dc_v2_yaml(2)" href="javascript:void(0);">订阅</a>  													
																</div>
															</td>
                                                    </tr>
                                                    <tr id="clash_trojan">
														<th>trojan节点</th>
															<td>
																<div style="display:table-cell;float: left;margin-left:0px;">
																	<span id="dc_trojan"></span>															
                                                                    <a type="button" style="vertical-align: middle; margin:-10px 10px;" class="ss_btn" style="cursor:pointer" onclick="dc_tj_yaml(2)" href="javascript:void(0);">订阅</a>  													
																</div>
															</td>
													</tr>
													<tr id="sc3in1">
														<th><br>SubConverter三合一转换
															<br>
															<br><em style="color: gold;">SS&nbsp;|&nbsp;SSR&nbsp;|&nbsp;V2ray订阅|&nbsp;Trojan订阅</em>
															<br><em style="color: gold;">内置Acl4ssr项目规则</em>	
															<br><em style="color: gold;">本地SubConverter进程转换</em>																
														</th>
														<td >																									
															<div class="SimpleNote" style="display:table-cell;float: left; width: 400px;">
																<label>emoji:</label>																
																<input id="merlinclash_dc_subconverter_emoji" type="checkbox" name="dc_subconverter_emoji" checked="checked">
																<label>启用udp:</label>																
																<input id="merlinclash_dc_subconverter_udp" type="checkbox" name="dc_subconverter_udp">
																<label>节点类型:</label>																
																<input id="merlinclash_dc_subconverter_append_type" type="checkbox" name="dc_subconverter_append_type">
																<label>节点排序:</label>																
																<input id="merlinclash_dc_subconverter_sort" type="checkbox" name="dc_subconverter_sort">
																<label>过滤非法节点:</label>																
																<input id="merlinclash_dc_subconverter_fdn" type="checkbox" name="dc_subconverter_fdn">
																<br>
																<label>跳过证书验证:</label>																
																<input id="merlinclash_dc_subconverter_scv" type="checkbox" name="dc_subconverter_scv">
																<label>TCP Fast Open:</label>																
																<input id="merlinclash_dc_subconverter_tfo" type="checkbox" name="dc_subconverter_tfo">
															</div>
															<div class="SimpleNote" style="display:table-cell;float: left; width: 400px;">
																<p><label>包含节点：</label>
																	<input id="merlinclash_dc_subconverter_include" class="input_25_table" style="width:320px" placeholder="&nbsp;筛选包含关键字的节点名，支持正则">
																</p>
																<br>
																<p><label>排除节点：</label>
																	<input id="merlinclash_dc_subconverter_exclude" class="input_25_table" style="width:320px" placeholder="&nbsp;过滤包含关键字的节点名，支持正则">
																</p>
															</div>
															<div class="SimpleNote" style="display:table-cell;float: left; height: 30px; line-height: 30px; ">
																<select id="merlinclash_dc_clashtarget" style="width:75px;margin:0px 0px 0px 2px;text-align:left;padding-left: 0px;" class="input_option">
																	<option value="clash">clash新参数</option>
																	<option value="clashr">clashR新参数</option>						
																</select>
																<select id="merlinclash_dc_acl4ssrsel" style="width:220px;margin:0px 0px 0px 2px;text-align:left;padding-left: 0px;" class="input_option">
																	<option value="ZHANG">Merlin Clash_常规规则</option>
																	<option value="ZHANG_NoAuto">Merlin Clash_常规无测速</option>
																	<option value="ZHANG_Media">Merlin Clash_多媒体全量</option>
																	<option value="ZHANG_Media_NoAuto">Merlin Clash_多媒体全量无测速</option>
																	<option value="ZHANG_Media_Area_UrlTest">Merlin Clash_多媒体全量分地区测速</option>
																	<option value="ZHANG_Media_Area_FallBack">Merlin Clash_多媒体全量分地区故障转移</option>
																	<option value="ACL4SSR_Online">Online默认版_分组比较全</option>
																	<option value="ACL4SSR_Online_AdblockPlus">AdblockPlus_更多去广告</option>	
																	<option value="ACL4SSR_Online_NoAuto">NoAuto_无自动测速</option>	
																	<option value="ACL4SSR_Online_NoReject">NoReject_无广告拦截规则</option>	
																	<option value="ACL4SSR_Online_Mini">Mini_精简版</option>	
																	<option value="ACL4SSR_Online_Mini_AdblockPlus">Mini_AdblockPlus_精简版更多去广告</option>	
																	<option value="ACL4SSR_Online_Mini_NoAuto">Mini_NoAuto_精简版无自动测速</option>
																	<option value="ACL4SSR_Online_Mini_Fallback">Mini_Fallback_精简版带故障转移</option>	
																	<option value="ACL4SSR_Online_Mini_MultiMode">Mini_MultiMode_精简版自动测速故障转移负载均衡</option>	
																	<option value="ACL4SSR_Online_Full">Full全分组_重度用户使用</option>
																	<option value="ACL4SSR_Online_Full_NoAuto">Full全分组_无自动测速</option>
																	<option value="ACL4SSR_Online_Full_AdblockPlus">Full全分组_更多去广告</option>
																	<option value="ACL4SSR_Online_Full_Netflix">Full全分组_奈飞全量</option>
																	<option value="ACL4SSR_Online_Full_Google">Full全分组_谷歌细分</option>
																	<option value="ACL4SSR_Online_Full_MultiMode">Full全分组_多模式</option>
																	<option value="ACL4SSR_Online_Mini_MultiCountry">Full全分组_多国家地区</option>																		
																</select>
															</div>
															<!--<div class="SimpleNote" style="display:table-cell;float: left; height: 30px; line-height: 30px; ">
																<label style="color: gold;">远程配置：</label>
																<input id="merlinclash_dc_uploadiniurl" class="input_25_table" style="width:185px" placeholder="&nbsp;请输入文件URL地址">
																<input id="merlinclash_dc_customurl_cbox" type="checkbox" name="merlinclash_dc_customurl_cbox"><span>&nbsp;勾选使用</span>
																<a type="button" style="vertical-align: middle; margin:-10px 10px;" class="ss_btn" style="cursor:pointer" onclick="get_online_yaml4(21)" href="javascript:void(0);">&nbsp;&nbsp;开始转换&nbsp;&nbsp;</a>
															</div>-->
														</td>
													</tr>
												</table>
												
												<div class="SimpleNote" style="margin-left:270px ; display:table-cell;float: left; height: 30px; line-height: 30px; ">
													<label style="color: gold;">远程配置：</label>
													<input id="merlinclash_dc_uploadiniurl" class="input_25_table" style="width:185px" placeholder="&nbsp;请输入文件URL地址">
													<input id="merlinclash_dc_customurl_cbox" type="checkbox" name="merlinclash_dc_customurl_cbox"><span>&nbsp;勾选使用</span>
													<a type="button" style="vertical-align: middle; margin:-10px 10px;" class="ss_btn" style="cursor:pointer" onclick="get_online_yaml4(21)" href="javascript:void(0);">&nbsp;&nbsp;开始转换&nbsp;&nbsp;</a>
												</div>
												
											</div>  
											
										</div>
										
										<!--底部按钮-->
										<div class="apply_gen" id="loading_icon">
											<img id="loadingIcon" style="display:none;" src="/images/InternetScan.gif">
										</div>
										<div id="delallowneracls_button" class="apply_gen">
											<input class="button_gen" type="button" onclick="delallaclconfigs()" value="全部删除">	
										</div>
										<div id="apply_button" class="apply_gen">
											<input class="button_gen" type="button" onclick="apply()" value="保存&启动">
										</div>																															
									</td>
								</tr>
							</table>
						</div>
					</td>
				</tr>
			</table>
		</td>
		<td width="10" align="center" valign="top"></td>
	</tr>
</table>
<div id="footer"></div>
</body>
</html>