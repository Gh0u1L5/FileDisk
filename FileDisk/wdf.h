/**
	@file	wd_irp.h
	@brief	Windows�������������������͸���.
	
	�ṩ���ͷ�ļ���Ŀ�������ṩһ�ײ�������WindowsDDK��
	���������������ͣ����ͷ�ļ��õ�DEVICE_OBJECT������
	�����������ͣ����Ա���ʹ��"wdm.h"����"ntifs.h"

	@author tan wen ̷��
	@date	2005-12-20
*/

#include <ntifs.h>

#ifndef _WIN_DRV_FILE_SYS_H_
#define _WIN_DRV_FILE_SYS_H_

#define WD_MIN(a,b) ((a)<(b)?(a):(b))
#define WD_MAX(a,b) ((a)>(b)?(a):(b))
#define WD_MAX_PATH 260

#define wd_true		TRUE
#define wd_false	FALSE
#define wd_null		NULL
typedef CHAR				wd_char;
typedef LONG				wd_long;
typedef ULONG			wd_ulong;
typedef ULONG			wd_dword;
typedef USHORT			wd_ushort;
typedef WCHAR			wd_wchar;
typedef ULONG			wd_size;
typedef PVOID				wd_pvoid;
typedef VOID				wd_void;
typedef BOOLEAN				wd_bool;
typedef ULONG				wd_dat32;
typedef USHORT				wd_dat16;
typedef UCHAR				wd_byte;
typedef UCHAR				wd_uchar;
typedef LONG					wd_int;
typedef UNICODE_STRING	wd_ustr;
typedef LARGE_INTEGER	wd_lgint;
typedef LONGLONG			wd_llong;
typedef DRIVER_OBJECT	wd_drv;
typedef DEVICE_OBJECT	wd_dev;
typedef DRIVER_OBJECT	wd_pdrv;
typedef PDEVICE_OBJECT	wd_pdev;
typedef FILE_OBJECT		wd_file;
typedef IO_STATUS_BLOCK				wd_io_stat_block;
typedef IO_STATUS_BLOCK				wd_io_stat;
typedef	FILE_BASIC_INFORMATION		wd_file_basic_infor;
typedef	FILE_STANDARD_INFORMATION	wd_file_standard_infor;
typedef PEPROCESS								wd_proc_id;
typedef FILE_NETWORK_OPEN_INFORMATION	wd_file_net_open_infor;
typedef PMDL						wd_pmdl;
typedef MDL						wd_mdl;
typedef	COMPRESSED_DATA_INFO	wd_compressed_data_info;
typedef FAST_IO_DISPATCH			wd_fio_disp;
typedef PDRIVER_DISPATCH			wd_disp_fuc;
typedef NTSTATUS			wd_stat;
typedef HANDLE				wd_hand;

// old
enum {
	wd_stat_suc =				STATUS_SUCCESS,
	wd_stat_path_not_found =	STATUS_OBJECT_PATH_NOT_FOUND,
	wd_stat_insufficient_res =	STATUS_INSUFFICIENT_RESOURCES,
	wd_stat_invalid_dev_req =		STATUS_INVALID_DEVICE_REQUEST,
	wd_stat_no_such_dev =			STATUS_NO_SUCH_DEVICE,
	wd_stat_image_already_loaded =	STATUS_IMAGE_ALREADY_LOADED,
	wd_stat_more_processing =	STATUS_MORE_PROCESSING_REQUIRED,
	wd_stat_pending =			STATUS_PENDING,
	wd_stat_invalid_param =		STATUS_INVALID_PARAMETER,
	wd_stat_end_of_file =		STATUS_END_OF_FILE 
};

_inline wd_bool wd_suc(wd_stat state)
{	return NT_SUCCESS(state);	}

#define in_			IN
#define out_		OUT
#define in			IN			// old
#define out			OUT			// old
#define optional_	OPTIONAL
#define optional	OPTIONAL	// old
#define wd_main		DriverEntry

// ���º�����ã�
#define wd_printf0 // �߼���ʾ��һ��������ʾ���ɲ���ʾ�Ĵ���
#define wd_printf1 // �м���ʾ��һ����ʾһ���Դ���򾯸�
#define wd_printf2 // �ͼ���ʾ��һ��������ʾ���ֳɹ�����
#define wd_printf3 // ������ʾ
#define wd_printf4 // ������ʾ
#define wd_printf5 // ������ʾ
//DbgPrint

// old
enum{ wd_dev_name_max_len = 64 };

_inline wd_llong wd_int64(wd_lgint num)
{	return num.QuadPart;	}
_inline wd_void wd_int64_set(wd_lgint num,wd_llong ac_num)
{	num.QuadPart = ac_num;	}
_inline wd_ulong wd_lgint_high(wd_lgint num)
{	return num.u.HighPart;	}
_inline wd_ulong wd_lgint_low(wd_lgint num)
{	return num.u.LowPart;	}

// old
typedef enum {
	wd_user_mode = UserMode,
	wd_kernel_mode = KernelMode
} wd_proc_mode;

enum {
	reg_ulong = REG_DWORD,
	reg_ustr = REG_SZ
};

enum { wd_access_mask_del = DELETE};

_inline wd_void wd_lgint_add(wd_lgint *a,wd_ulong b)
{	a->QuadPart += b;	}
_inline wd_void wd_lgint_dec(wd_lgint *a,wd_ulong b)
{	a->QuadPart -= b;	}
_inline wd_void wd_lgint_from_llong(wd_lgint *a,wd_llong b)
{	a->QuadPart = b;	}
_inline wd_lgint wd_lgint_create(wd_llong b)
{
	wd_lgint a;
	a.QuadPart = b;
	return a;
}
_inline wd_ulong wd_lgint_low_set(wd_lgint *num,wd_ulong low)
{	return num->u.LowPart = low;	}
_inline wd_ulong wd_lgint_high_set(wd_lgint *num,wd_ulong high)
{	return num->u.HighPart = high;	}

/*
extern wd_stat g_wd_err;
_inline wd_void wd_set_err(wd_stat err)
{	g_wd_err = err;	}

_inline wd_stat wd_get_err()
{	return g_wd_err; }
*/

#endif //_WIN_DRV_FILE_SYS_H_