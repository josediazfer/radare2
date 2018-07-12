#include <windows.h>
#include <r_lib.h>
#include <r_cons.h>
#include <r_util.h>

static void draw_rect_win(HWND hwnd) {
	RECT rect;
	HDC hdc = NULL;
	INT pen_w;
	INT old_hdc = NULL;
	HPEN pen;
	HBRUSH brush;

	GetWindowRect (hwnd, &rect);
	hdc = GetWindowDC (hwnd);
	if (!hdc) {
		r_sys_perror ("darw_rect_win/GetWindowDC");
		goto err_draw_rect_win;
	}
	pen_w = GetSystemMetrics (SM_CXBORDER) * 3;
	old_hdc = SaveDC (hdc);
	// Get an inversion effect.
	SetROP2 (hdc, R2_NOT);
	pen = CreatePen (PS_INSIDEFRAME, pen_w, RGB (0x00, 0x00, 0x00));
	SelectObject (hdc, pen);
	brush = GetStockObject (NULL_BRUSH);
	SelectObject (hdc, brush);
        // Draw the rectangle.
	Rectangle (hdc, 0, 0, rect.right - rect.left, rect.bottom - rect.top);
	// Cleanup.
	DeleteObject (pen);
err_draw_rect_win:
	if (hdc) {
		if (old_hdc) {
        		RestoreDC (hdc, old_hdc);
		}
        	ReleaseDC (hwnd, hdc);
	}
}

static HWND last_win_hwnd = NULL;
static DWORD last_pid = 0;
static bool capturing = false;

LRESULT CALLBACK dlg_dbg_attach_msg(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
	bool pass_msg = false;
	int ret = 0;

	//eprintf ("MSG: %d\n", msg);
	switch (msg) {
	case WM_PAINT:
	{
		PAINTSTRUCT ps;
		HDC hdc = BeginPaint (hwnd,  &ps);
		RECT cli_rect;
		HRGN bgRgn;
		HBRUSH hBrush;

        	GetClientRect (hwnd, &cli_rect);
        	bgRgn = CreateRectRgnIndirect (&cli_rect);
        	hBrush = CreateSolidBrush (RGB (200,200,200));
        	FillRgn (hdc, bgRgn, hBrush);
		pass_msg = false;
		break;
	}
	case WM_MOUSEMOVE:
	{
		POINT cursor_pos;
		HWND win_hwnd;
		DWORD win_proc_id = 0;

		if (!capturing) {
			break;
		}
		SetCapture (hwnd);
		GetCursorPos (&cursor_pos);
		win_hwnd = WindowFromPoint (cursor_pos);
		if (win_hwnd != last_win_hwnd) {
			if (last_win_hwnd) {
				draw_rect_win (last_win_hwnd);
			}
			GetWindowThreadProcessId (win_hwnd, &win_proc_id);
			if (GetCurrentProcessId () != win_proc_id) {
				draw_rect_win (win_hwnd);
				last_win_hwnd = win_hwnd;
				last_pid = win_proc_id;
			} else {
				last_pid = 0;
				last_win_hwnd = NULL;
				pass_msg = true;
			}
		}
		break;
	}
	case WM_LBUTTONDOWN:
	{
		HCURSOR hwnd_cursor;

		if (last_win_hwnd) {
			draw_rect_win (last_win_hwnd);
			last_win_hwnd = NULL;

		}
		SetCapture (hwnd);
		hwnd_cursor = LoadCursor (NULL, IDC_CROSS);	
		if (hwnd_cursor) {
			SetCursor (hwnd_cursor);
		}
		capturing = true;
		break;
	}
	case WM_LBUTTONUP:
	{
		HCURSOR hwnd_cursor;

		ReleaseCapture ();
		if (last_pid > 0) {
			PostMessage (hwnd, WM_APP + 2, last_pid, 0);
		}
		hwnd_cursor = LoadCursor (NULL, IDC_ARROW);	
		if (hwnd_cursor) {
			SetCursor (hwnd_cursor);
		}
		if (last_win_hwnd) {
			draw_rect_win (last_win_hwnd);
			last_win_hwnd = NULL;
		}
		capturing = false;
		break;
	}
	default:
		pass_msg = true;
	}
	if (pass_msg) {
		ret = DefWindowProc (hwnd, msg, wparam, lparam);
	}
	return ret;
}

static void dlg_dbg_attach_intr(void *h) {
	PostMessage ((HWND)h, WM_APP + 1, 0, 0);
}

int dlg_dbg_attach()
{
	WNDCLASSEX wcx = { 0 }; 
	HWND hwnd = NULL;
	BOOL msg_code;
	MSG msg = { 0 };
	int pid = 0;
 
	wcx.cbSize = sizeof(wcx);
	wcx.style = CS_HREDRAW | CS_VREDRAW;
	wcx.lpfnWndProc = dlg_dbg_attach_msg;
    	wcx.hIcon = LoadIcon(NULL, 
        IDI_APPLICATION); 
    	wcx.hCursor = LoadCursor(NULL, 
        IDC_ARROW);                    // predefined arrow 
	wcx.lpszMenuName =  TEXT("MainMenu");    // name of menu resource 
	wcx.lpszClassName = TEXT("MainWClass");  // name of window class 
	wcx.hIconSm = LoadImage(NULL, // small class icon 
        MAKEINTRESOURCE(5),
        IMAGE_ICON, 
        GetSystemMetrics(SM_CXSMICON), 
        GetSystemMetrics(SM_CYSMICON), 
        LR_DEFAULTCOLOR); 
	if (!RegisterClassEx (&wcx)) {
		r_sys_perror ("dlg_dbg_attach/RegisterClassEx");
		goto err_dlg_dbg_attach;
	}
	hwnd = CreateWindow( 
        	TEXT ("MainWClass"),        // name of window class 
        	TEXT ("Radare - Press mouse left button to attach to a process..."),            // title-bar string 
        	WS_OVERLAPPED | WS_CAPTION | WS_SIZEBOX | WS_SYSMENU, // top-level window 
        	CW_USEDEFAULT,       // default horizontal position 
        	CW_USEDEFAULT,       // default vertical position 
        	400,       // width 
        	100,       // height 
        	(HWND) NULL,         // no owner window 
        	(HMENU) NULL,        // use class menu 
        	NULL,           // handle to application instance 
        	(LPVOID) NULL);      // no window-creation data 
    	if (!hwnd) {
		r_sys_perror ("dlg_dbg_attach/CreateWindow");
		goto err_dlg_dbg_attach;
	}
	ShowWindow (hwnd, SW_SHOW);
	UpdateWindow (hwnd);
	eprintf ("waiting for attach to a process....");
	r_cons_break_push (dlg_dbg_attach_intr, hwnd);
	while ((msg_code = GetMessage (&msg, hwnd, 0, 0)) != 0 && msg_code != -1 && msg.message != WM_APP + 1 && msg.message != WM_APP + 2) { 
		TranslateMessage (&msg); 
		DispatchMessage (&msg);
	} 
	if (msg.message == WM_APP + 2) {
		pid = (int)msg.wParam;
	}
    	r_cons_break_pop ();
err_dlg_dbg_attach:
	if (hwnd) {
		DestroyWindow (hwnd);
	}
	return pid;
}
