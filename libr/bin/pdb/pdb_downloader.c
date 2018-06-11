/* radare - LGPL - Copyright 2014-2017 - inisider */

#include <string.h>
#include <r_util.h>
#include <r_core.h>
#include <winhttp.h>
#include "pdb_downloader.h"

static bool checkPrograms () {
#if __WINDOWS__ && !__CYGWIN__
	if (r_sys_cmd ("expand -? >nul") != 0) {
		return false;
	}
#else
	const char nul[] = "/dev/null";
	if (r_sys_cmd ("cabextract -v > /dev/null") != 0) {
		return false;
	}
	if (r_sys_cmdf ("curl --version > %s", nul) != 0) {
		return false;
	}
#endif
	return true;
}

static int w32_download(struct SPDBDownloaderOpt *opt, char *archive_name, int archive_name_len, const char *basepath, char *abspath_to_archive, char **extractor_cmd) {
	const char *cabextractor = "expand";
	const char *format = "%s %s %s";
	HINTERNET h_ses = NULL, h_req = NULL, h_con = NULL;
	LPTSTR user_agent = NULL;
	LPWSTR url = NULL;
	int res = 0;
	DWORD ret_bytes;
	BYTE *buff = NULL;
	FILE *fd = NULL;
	char *abspath_to_file = NULL;
	URL_COMPONENTS url_comp = {0};
	WINHTTP_CURRENT_USER_IE_PROXY_CONFIG ie_proxy_conf = {0};
	LPWSTR hostname = NULL, path = NULL, url_path = NULL;
	char *url_path_ = NULL;
	DWORD status_code, flags;
	DWORD status_code_sz = sizeof (status_code);
	WINHTTP_PROXY_INFO proxy_inf = {0};
	WINHTTP_AUTOPROXY_OPTIONS auto_proxy_opt = {0};

	user_agent = r_sys_conv_utf8_to_utf16 (opt->user_agent);
	url = r_sys_conv_utf8_to_utf16 (opt->symbol_server);
	url_comp.dwStructSize = sizeof (url_comp);
	url_comp.dwHostNameLength = (DWORD)-1;
	url_comp.dwUrlPathLength = (DWORD)-1;
//	eprintf ("URL: %ws\n", url);

	if (!WinHttpCrackUrl (url, 0, 0, &url_comp)) {
		r_sys_perror_strf ("w32_download/WinHttpCrackUrl",
				"(%d) url: %s",
				GetLastError(),
				opt->symbol_server);
		goto err_w32_download;
	}
	h_ses = WinHttpOpen (user_agent, WINHTTP_ACCESS_TYPE_NO_PROXY,
					 WINHTTP_NO_PROXY_NAME,
					 WINHTTP_NO_PROXY_BYPASS,
					 0);
	if (!h_ses) {
		r_sys_perror_strf ("w32_download/WinHttpOpen", "(%d)", GetLastError());
		goto err_w32_download;
	}
	hostname = (LPTSTR)calloc (1, sizeof (WCHAR) * (url_comp.dwHostNameLength + 1));
	if (!hostname) {
		perror ("w32_download/alloc hostname");
		goto err_w32_download;
	}
	memcpy (hostname, url_comp.lpszHostName, sizeof (WCHAR) * url_comp.dwHostNameLength);
	h_con = WinHttpConnect (h_ses, hostname, url_comp.nPort, 0);
	if (!h_con) {
		r_sys_perror_strf ("w32_download/WinHttpConnect",
				"(%d) url: %ws hostname: %ws port :%d",
				GetLastError(),
				url,
				url_comp.lpszHostName,
				url_comp.nPort);
		goto err_w32_download;
	}
	path = (LPWSTR)calloc (1, sizeof (WCHAR) * url_comp.dwUrlPathLength + 1);
	if (!path) {
		perror ("w32_download/alloc path");
		goto err_w32_download;
	}
	memcpy (path, url_comp.lpszUrlPath, sizeof (WCHAR) * url_comp.dwUrlPathLength);
	url_path_ = r_str_newf ("%ws/%s/%s/%s",
					path,
					opt->dbg_file,
					opt->guid,
					archive_name);

	url_path = r_sys_conv_utf8_to_utf16 (url_path_);
	//eprintf ("url path: %ws\n", url_path);
	flags = 0;
	if (url_comp.nScheme == INTERNET_SCHEME_HTTPS) {
		flags |= WINHTTP_FLAG_SECURE;
	}
	h_req = WinHttpOpenRequest (h_con, TEXT ("GET"), url_path,
					TEXT ("HTTP/1.1"), WINHTTP_NO_REFERER,
					WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
	if (!h_req) {
		r_sys_perror_strf ("w32_download/WinHttpOpenRequest",
				"(%d) %ws",
				GetLastError(),
				url_path);
		goto err_w32_download;
	}
	if (WinHttpGetIEProxyConfigForCurrentUser (&ie_proxy_conf)) {
		auto_proxy_opt.fAutoLogonIfChallenged = TRUE;
		if (ie_proxy_conf.lpszAutoConfigUrl) {
			auto_proxy_opt.dwFlags = WINHTTP_AUTOPROXY_CONFIG_URL;
			auto_proxy_opt.lpszAutoConfigUrl = ie_proxy_conf.lpszAutoConfigUrl;
		} else if (ie_proxy_conf.fAutoDetect) {
			auto_proxy_opt.dwFlags = WINHTTP_AUTOPROXY_AUTO_DETECT;
			auto_proxy_opt.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP |
							WINHTTP_AUTO_DETECT_TYPE_DNS_A;
		} else if (ie_proxy_conf.lpszProxy) {
			proxy_inf.dwAccessType = WINHTTP_ACCESS_TYPE_NO_PROXY;
			if (ie_proxy_conf.lpszProxy) {
				proxy_inf.lpszProxy = wcsdup (ie_proxy_conf.lpszProxy);
			}
			if (ie_proxy_conf.lpszProxyBypass) {
				proxy_inf.lpszProxyBypass = wcsdup (ie_proxy_conf.lpszProxyBypass);
			}
		}
		if (auto_proxy_opt.dwFlags) {
			if (!WinHttpGetProxyForUrl (h_ses, url, &auto_proxy_opt, &proxy_inf)) {
				r_sys_perror_strf ("w32_download/WinHttpGetProxyForUrl",
						"(%d) url: %ws",
						GetLastError(),
						url);
				goto err_w32_download;
			}
		}
		if (!WinHttpSetOption (h_req, WINHTTP_OPTION_PROXY,
					&proxy_inf,
					sizeof (proxy_inf))) {
			r_sys_perror_strf ("w32_download/WinHttpSetOption",
						"(%d)", GetLastError());
			goto err_w32_download;
		}
	}
	if (!WinHttpSendRequest (h_req, NULL, 0, NULL, 0, 0, (DWORD_PTR)NULL)) {
		r_sys_perror_strf ("w32_download/WinHttpSendRequest", "(%d)", GetLastError());
		goto err_w32_download;
	}
	if (!WinHttpReceiveResponse (h_req, NULL)) {
		r_sys_perror_strf ("w32_download/WinHttpReceiveResponse", "(%d)", GetLastError());
		goto err_w32_download;
	}
	fd = fopen (abspath_to_archive, "wb");
	if (!fd) {
		perror ("w32_download/fopen");
		goto err_w32_download;
	}
	if (!WinHttpQueryHeaders (h_req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
					WINHTTP_HEADER_NAME_BY_INDEX,
					&status_code, &status_code_sz,
					WINHTTP_NO_HEADER_INDEX)) {
		r_sys_perror_strf ("w32_download/WinHttpQueryHeaders", "(%d)", GetLastError());
		goto err_w32_download;
	}
	res = status_code;
	if (status_code != 200) {
		goto err_w32_download;
	}
	while (WinHttpQueryDataAvailable (h_req, &ret_bytes) && ret_bytes > 0) {
		DWORD ret_read;

		buff = (BYTE *)malloc (ret_bytes);
		if (!buff) {
			perror ("w32_download/alloc buff");
			goto err_w32_download;
		}
		if (!WinHttpReadData (h_req, buff, ret_bytes, &ret_read)) {
			r_sys_perror_strf ("w32_download/WinHttpReadFile", "(%d)", GetLastError());
			goto err_w32_download;
		}
		fwrite (buff, ret_read, 1, fd);
		R_FREE (buff);
	}
	abspath_to_file = strdup (abspath_to_archive);
	if (abspath_to_file) {
		int abspath_to_archive_len = archive_name_len + strlen (basepath) + 2;
		abspath_to_file[abspath_to_archive_len - 2] = 'b';
		// extact_cmd -> %1 %2 %3
		// %1 - 'expand'
		// %2 - absolute path to archive
		// %3 - absolute path to file that will be dearchive
		*extractor_cmd = r_str_newf (format, cabextractor,
			abspath_to_archive, abspath_to_file);
	}
err_w32_download:
	free (user_agent);
	free (url_path);
	free (url_path_);
	free (hostname);
	free (url);
	free (buff);
	free (abspath_to_file);
	if (ie_proxy_conf.lpszProxy) {
		GlobalFree (ie_proxy_conf.lpszProxy);
	}
	if (ie_proxy_conf.lpszProxyBypass) {
		GlobalFree (ie_proxy_conf.lpszProxyBypass);
	}
	if (ie_proxy_conf.lpszAutoConfigUrl) {
		GlobalFree (ie_proxy_conf.lpszAutoConfigUrl);
	}
	if (proxy_inf.lpszProxy) {
		GlobalFree (proxy_inf.lpszProxy);
	}
	if (proxy_inf.lpszProxyBypass) {
		GlobalFree (proxy_inf.lpszProxyBypass);
	}
	if (fd) {
		fclose (fd);
	}
	if (h_req) {
		WinHttpCloseHandle (h_req);
	}
	if (h_con) {
		WinHttpCloseHandle (h_con);
	}
	if (h_ses) {
		WinHttpCloseHandle (h_ses);
	}
	if (res != 200 && fd) {
		LPTSTR abspath_to_archive_ = r_sys_conv_utf8_to_utf16 (abspath_to_archive);
		DeleteFile (abspath_to_archive_);
	}
	return res;
}

static int download(struct SPDBDownloader *pd) {
	SPDBDownloaderOpt *opt = pd->opt;
	char *extractor_cmd = NULL;
	char *abspath_to_archive = NULL;
	char *archive_name = NULL;
	char *basepath = NULL;
	int res = 0, archive_name_len = 0;
	if (!opt->dbg_file || !*opt->dbg_file || !checkPrograms()) {
		// no pdb debug file
		return 0;
	}
	// dbg_file len is > 0
	archive_name_len = strlen (opt->dbg_file);
	archive_name = malloc (archive_name_len+1);
	if (!archive_name) {
		return 0;
	}
	memcpy (archive_name, opt->dbg_file, archive_name_len+1);
	if (opt->cache_dir && *opt->cache_dir) {
		basepath = r_str_newf ("%s"R_SYS_DIR"%s"R_SYS_DIR"%s", opt->cache_dir, archive_name, opt->guid);
		if (!r_sys_mkdirp (basepath)) {
			eprintf ("unable to create pdb cache directory path %s\n", basepath);
			goto err_download; 
		}
	} else if (opt->path && *opt->path) {
		basepath = strdup(opt->path);
	} else {
		basepath = strdup(".");
	}
	archive_name[archive_name_len - 1] = '_';
	abspath_to_archive = r_str_newf ("%s%s%s", basepath,
		R_SYS_DIR, archive_name);
#if __WINDOWS__ && !__CYGWIN__
	res = w32_download (opt, archive_name, archive_name_len, basepath, abspath_to_archive, &extractor_cmd);
	/* not found? try get uncompressed pdb file */
	if (res == 404) {
		free (extractor_cmd);
		memcpy (archive_name, opt->dbg_file, archive_name_len + 1);
		res = w32_download (opt, archive_name, archive_name_len, basepath, abspath_to_archive, &extractor_cmd);
	}
	res = res == 200? 1 : 0;
#else
	const char *cabextractor = "cabextract";
	const char *format = "%s -d \"%s\" \"%s\"";
	char *curl_cmd = r_str_newf ("curl -sA \"%s\" \"%s/%s/%s/%s\" -o \"%s\"",
			opt->user_agent,
			opt->symbol_server,
			opt->dbg_file,
			opt->guid,
			archive_name,
			abspath_to_archive);
	// eprintf ("%s\n", curl_cmd);
	// cabextract -d %1 %2
	// %1 - path to directory where to extract all files from cab arhcive
	// %2 - absolute path to cab archive
	extractor_cmd = r_str_newf (format,
		cabextractor, basepath, abspath_to_archive);
	if (r_sys_cmd (curl_cmd) != 0) {
		eprintf("curl has not been finish with success\n");
	} else {
		res = 1;
	}	
	free (curl_cmd);
#endif
	if (opt->extract > 0) {
		if (res && (r_sys_cmd (extractor_cmd) != 0)) {
			eprintf ("cab extrach has not been finished with success\n");
			res = 0;
		}
		r_file_rm (abspath_to_archive);
	}
err_download:
	free (basepath);
	free (archive_name);
	free (extractor_cmd);
	free (abspath_to_archive);
	return res;
}

void init_pdb_downloader(SPDBDownloaderOpt *opt, SPDBDownloader *pd) {
	pd->opt = R_NEW0 (SPDBDownloaderOpt);
	if (!pd->opt) {
		return;
	}
	pd->opt->dbg_file = strdup (opt->dbg_file);
	pd->opt->guid = strdup (opt->guid);
	pd->opt->symbol_server = strdup (opt->symbol_server);
	pd->opt->user_agent = strdup (opt->user_agent);
	pd->opt->path = strdup (opt->path);
	pd->opt->cache_dir = strdup (opt->cache_dir);
	pd->opt->extract = opt->extract;
	pd->download = download;
}

void deinit_pdb_downloader(SPDBDownloader *pd) {
	R_FREE (pd->opt->dbg_file);
	R_FREE (pd->opt->guid);
	R_FREE (pd->opt->symbol_server);
	R_FREE (pd->opt->user_agent);
	R_FREE (pd->opt->path);
	R_FREE (pd->opt);
	pd->download = 0;
}

char *r_bin_pdb_cached_get(RCore *core, SPDBOptions *options) {
	RBinInfo *info = r_bin_get_info (core->bin);
	char *path;
	bool exists;

	if (!options->cache_dir || !*options->cache_dir) {
		return false;
	}
	path = r_str_newf ("%s"R_SYS_DIR"%s"R_SYS_DIR"%s"R_SYS_DIR"%s",
				options->cache_dir,
				info->debug_file_name,
				info->guid,
				info->debug_file_name);
	if (!(exists = r_file_exists (path))) {
		path[strlen (path) - 1] = '_';
		exists = r_file_exists (path);
		if (!exists) {
			R_FREE (path);
		}
	}
	return path;
}

int r_bin_pdb_download(RCore* core, int isradjson, int* actions_done, SPDBOptions* options) {
	int ret;
	char *path;
	SPDBDownloaderOpt opt;
	SPDBDownloader pdb_downloader;
	RBinInfo *info = r_bin_get_info (core->bin);

	if (!info || !info->debug_file_name) {
		eprintf ("Can't find debug filename\n");
		return 1;
	}

	if (!options || !options->symbol_server || !options->user_agent) {
		eprintf ("Can't retrieve pdb configurations\n");
		return 1;
	}

	path = info->file ? r_file_dirname (info->file) : strdup (".");

	opt.dbg_file = info->debug_file_name;
	opt.guid = info->guid;
	opt.symbol_server = options->symbol_server;
	opt.user_agent = options->user_agent;
	opt.cache_dir = options->cache_dir;
	opt.path = path;
	opt.extract = options->extract;

	init_pdb_downloader (&opt, &pdb_downloader);
	ret = pdb_downloader.download (&pdb_downloader);
	if (isradjson && actions_done) {
		printf ("%s\"pdb\":{\"file\":\"%s\",\"download\":%s}",
			*actions_done ? "," : "", opt.dbg_file, ret ? "true" : "false");
	} else {
		printf ("PDB \"%s\" download %s\n",
			opt.dbg_file, ret ? "success" : "failed");
	}
	if (actions_done) {
		(*actions_done)++;
	}
	deinit_pdb_downloader (&pdb_downloader);

	free (path);
	return 0;
}
