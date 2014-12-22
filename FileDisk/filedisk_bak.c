/*
    This is a virtual disk driver for Windows that uses one or more files to
    emulate physical disks.
    Copyright (C) 1999-2009 Bo Brant閚.
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include <ntddk.h>
#include <ntdddisk.h>
#include <ntddcdrm.h>
#include <ntverp.h>
#include <wdmsec.h>
#include "wdf.h"

#define WD_USTR_BUF_LEN 64
#define WD_USTR_APD_LEN 8

STRING Keys[26];
typedef unsigned char Byte;

typedef struct wd_ustr_block_
{
	wd_ustr ustr;
	wd_wchar *buf;
	wd_ulong buf_len;
} wd_ustr_block;
#define WD_MAX(a,b) ((a)>(b)?(a):(b))

_inline wd_pvoid wd_malloc(wd_bool paged,wd_size size)
{	return ExAllocatePool(paged?PagedPool:NonPagedPool,size);	}
_inline wd_void	wd_free(wd_pvoid point)
{		ExFreePool(point);	};
void* wd_ustr_h_alloc(const wd_wchar *str)
{
	wd_ustr_block *block = 
		(wd_ustr_block *)wd_malloc(wd_false,sizeof(wd_ustr_block));
	wd_wchar *buf = NULL;
	size_t buf_len = WD_MAX(wcslen(str)+WD_USTR_APD_LEN,WD_USTR_BUF_LEN);

	if(NULL == block)
		return NULL;
	buf = (wd_wchar *)wd_malloc(wd_false,buf_len*sizeof(wd_wchar));
	if(buf == NULL)
	{
		wd_free(block);
		return NULL;
	}
	wcscpy(buf,str);
	RtlInitUnicodeString(&block->ustr,buf);
	block->buf = buf;
	block->buf_len = buf_len;
	return (void *)block;
}
wd_void wd_ustr_h_free(void *str)
{
	wd_ustr_block *block = (wd_ustr_block *)str;
	if(str == NULL)
		return;
	if(block->buf)
		wd_free(block->buf);
	wd_free(block);
}
void* wd_ustr_h_alloc_from_ustr(const wd_ustr *ustr)
{
	wd_ustr_block *block = 
		(wd_ustr_block *)wd_malloc(wd_false,sizeof(wd_ustr_block));
	wd_wchar *buf = NULL;
	wd_wchar buf_len = 
		WD_MAX(ustr->Length+WD_USTR_APD_LEN,WD_USTR_BUF_LEN);

	if(NULL == block)
		return NULL;
	buf = (wd_wchar *)wd_malloc(wd_false,buf_len*sizeof(wd_wchar));
	if(buf == NULL)
	{
		wd_free(block);
		return NULL;
	}

	block->buf = buf;
	block->buf_len = buf_len;
	RtlInitEmptyUnicodeString(&block->ustr,block->buf,buf_len*sizeof(wd_char));

	// Because an UNICODE_STRING is not always with a NULL 
	// terminated wchar,so I used wd_ustr_copy(), did not 
	// use wd_wchar_str_copy().
	RtlCopyUnicodeString(&block->ustr,ustr);
	block->buf[ustr->Length] = L'\0';
	return (void *)block;
};

wd_ustr *wd_ustr_h_ustr(void *str)
{
	wd_ustr_block *block = (wd_ustr_block *)str;
	return &block->ustr;
}
wd_wchar *wd_ustr_h_buf(void *str)
{
	wd_ustr_block *block = (wd_ustr_block *)str;
	return block->buf;
}
void* wd_obj_query_name(in_ wd_void *obj)
{
    wd_stat status;
    wd_byte nibuf[512];
	wd_int len = 260;
	wd_ulong ret;

    OBJECT_NAME_INFORMATION * name_infor = (OBJECT_NAME_INFORMATION *)nibuf;
    status = ObQueryNameString(obj,name_infor,512,&ret);
    if (wd_suc(status)) 
	{
        return wd_ustr_h_alloc_from_ustr( &name_infor->Name );
    }
	else
	{
		return NULL;
	}
}


void* wd_symbolic_target_ustr(wd_ustr *symbolic)
{
	OBJECT_ATTRIBUTES attributes;
	wd_stat status;
	wd_wchar buf[8];
	wd_wchar *dbuf = NULL;
	wd_ustr target;
	void * target_ret = NULL;
	wd_ulong length;
	HANDLE link_handle;
	InitializeObjectAttributes(
	&attributes, 
	symbolic,
	OBJ_KERNEL_HANDLE|OBJ_CASE_INSENSITIVE,
	NULL,NULL);
	status = ZwOpenSymbolicLinkObject(
	&link_handle,
	GENERIC_READ,
	&attributes);
	if(!wd_suc(status))
		return NULL;
	RtlInitEmptyUnicodeString(&target, buf, 8* sizeof(wd_wchar));
	status = ZwQuerySymbolicLinkObject(link_handle, &target, &length);
	if(status == STATUS_BUFFER_TOO_SMALL)
	{
		dbuf = (wd_wchar *)wd_malloc(wd_false,length+2);
		if(dbuf == NULL)
		{
			ZwClose(link_handle);
			return NULL;
		}
		RtlInitEmptyUnicodeString(&target, dbuf, length+2);
		status = ZwQuerySymbolicLinkObject(link_handle, &target, &length);
	}
	if(wd_suc(status))
	{
		target_ret = wd_ustr_h_alloc_from_ustr(&target);
	}
	if(dbuf != NULL)
		wd_free(dbuf);
	ZwClose(link_handle);
	return target_ret;
}
void* wd_symbolic_target(wd_wchar *symbolic)
{
	void *sym;
	void *ret;
	if(symbolic == NULL)
		return NULL;
	sym	= wd_ustr_h_alloc(symbolic);
	if(sym == NULL)
		return NULL;
	ret = wd_symbolic_target_ustr(wd_ustr_h_ustr(sym));
	wd_ustr_h_free(sym);
	return ret;
}
void* wd_vol_name_dos_name(wd_wchar *name)
{
	wd_wchar vol_syb[] = { L"\\DosDevices\\X:" };
	wd_ustr vol_name;
	wd_wchar c; 
	if(name == NULL)
		return NULL;
	RtlInitUnicodeString(&vol_name, name);
	for(c = L'A'; c < ('Z'+1); ++c)
	{
		void * my_target = NULL;
		vol_syb[12] = c;
		my_target = wd_symbolic_target(vol_syb);
		if( my_target != NULL && 
		RtlCompareUnicodeString(wd_ustr_h_ustr(my_target), &vol_name, wd_true) == 0 )
		{
			wd_ustr_h_free(my_target);
			break;
		}
		if(my_target != NULL)
		{
			wd_printf0("FF:%wZrn",wd_ustr_h_ustr(my_target));
			wd_ustr_h_free(my_target);
		}
	}
	if(c == 'Z'+1)
		return NULL;
	else
		return wd_ustr_h_alloc(&vol_syb[12]);
}
void* wd_vol_dos_name_safe(wd_dev *dev)
{
	void* vol_name = wd_obj_query_name(dev);
	void* ret = NULL;
	if(vol_name == NULL)
		return NULL;
	ret = wd_vol_name_dos_name(wd_ustr_h_buf(vol_name));
	wd_ustr_h_free(vol_name);
	return ret;
}

//
// We include some stuff from newer DDK:s here so that one
// version of the driver for all versions of Windows can
// be compiled with the Windows NT 4.0 DDK.
//
#if (VER_PRODUCTBUILD < 2195)

#define FILE_DEVICE_MASS_STORAGE            0x0000002d
#define IOCTL_STORAGE_CHECK_VERIFY2         CTL_CODE(IOCTL_STORAGE_BASE, 0x0200, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FILE_ATTRIBUTE_ENCRYPTED            0x00004000

#endif

#if (VER_PRODUCTBUILD < 2600)

#define IOCTL_DISK_GET_PARTITION_INFO_EX    CTL_CODE(IOCTL_DISK_BASE, 0x0012, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DISK_GET_LENGTH_INFO          CTL_CODE(IOCTL_DISK_BASE, 0x0017, METHOD_BUFFERED, FILE_READ_ACCESS)

typedef enum _PARTITION_STYLE {
    PARTITION_STYLE_MBR,
    PARTITION_STYLE_GPT
} PARTITION_STYLE;

typedef unsigned __int64 ULONG64, *PULONG64;

typedef struct _PARTITION_INFORMATION_MBR {
    UCHAR   PartitionType;
    BOOLEAN BootIndicator;
    BOOLEAN RecognizedPartition;
    ULONG   HiddenSectors;
} PARTITION_INFORMATION_MBR, *PPARTITION_INFORMATION_MBR;

typedef struct _PARTITION_INFORMATION_GPT {
    GUID    PartitionType;
    GUID    PartitionId;
    ULONG64 Attributes;
    WCHAR   Name[36];
} PARTITION_INFORMATION_GPT, *PPARTITION_INFORMATION_GPT;

typedef struct _PARTITION_INFORMATION_EX {
    PARTITION_STYLE PartitionStyle;
    LARGE_INTEGER   StartingOffset;
    LARGE_INTEGER   PartitionLength;
    ULONG           PartitionNumber;
    BOOLEAN         RewritePartition;
    union {
        PARTITION_INFORMATION_MBR Mbr;
        PARTITION_INFORMATION_GPT Gpt;
    };
} PARTITION_INFORMATION_EX, *PPARTITION_INFORMATION_EX;

typedef struct _GET_LENGTH_INFORMATION {
    LARGE_INTEGER Length;
} GET_LENGTH_INFORMATION, *PGET_LENGTH_INFORMATION;

#endif // (VER_PRODUCTBUILD < 2600)

//
// We include some stuff from ntifs.h here so that
// the driver can be compiled with only the DDK.
//

#define PsDereferenceImpersonationToken(T)  \
            {if (ARGUMENT_PRESENT(T)) {     \
                (ObDereferenceObject((T))); \
            } else {                        \
                ;                           \
            }                               \
}

#define PsDereferencePrimaryToken(T) (ObDereferenceObject((T)))

NTKERNELAPI
VOID
PsRevertToSelf (
    VOID
);

NTKERNELAPI
NTSTATUS
SeCreateClientSecurity (
    IN PETHREAD                     Thread,
    IN PSECURITY_QUALITY_OF_SERVICE QualityOfService,
    IN BOOLEAN                      RemoteClient,
    OUT PSECURITY_CLIENT_CONTEXT    ClientContext
);

#define SeDeleteClientSecurity(C)  {                                           \
            if (SeTokenType((C)->ClientToken) == TokenPrimary) {               \
                PsDereferencePrimaryToken( (C)->ClientToken );                 \
            } else {                                                           \
                PsDereferenceImpersonationToken( (C)->ClientToken );           \
            }                                                                  \
}

NTKERNELAPI
VOID
SeImpersonateClient (
    IN PSECURITY_CLIENT_CONTEXT ClientContext,
    IN PETHREAD                 ServerThread OPTIONAL
);

NTKERNELAPI
TOKEN_TYPE
SeTokenType (
    IN PACCESS_TOKEN Token
);

#ifndef SE_IMPERSONATE_PRIVILEGE
#define SE_IMPERSONATE_PRIVILEGE        (29L)
#endif

#define TOKEN_ASSIGN_PRIMARY            (0x0001)
#define TOKEN_DUPLICATE                 (0x0002)
#define TOKEN_IMPERSONATE               (0x0004)
#define TOKEN_QUERY                     (0x0008)
#define TOKEN_QUERY_SOURCE              (0x0010)
#define TOKEN_ADJUST_PRIVILEGES         (0x0020)
#define TOKEN_ADJUST_GROUPS             (0x0040)
#define TOKEN_ADJUST_DEFAULT            (0x0080)

NTSYSAPI
NTSTATUS
NTAPI
ZwOpenProcessToken (
    IN HANDLE       ProcessHandle,
    IN ACCESS_MASK  DesiredAccess,
    OUT PHANDLE     TokenHandle
);

NTSYSAPI
NTSTATUS
NTAPI
NtAdjustPrivilegesToken (
    IN HANDLE               TokenHandle,
    IN BOOLEAN              DisableAllPrivileges,
    IN PTOKEN_PRIVILEGES    NewState,
    IN ULONG                BufferLength,
    OUT PTOKEN_PRIVILEGES   PreviousState OPTIONAL,
    OUT PULONG              ReturnLength
);

#define FSCTL_SET_SPARSE CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 49, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

NTSYSAPI
NTSTATUS
NTAPI
ZwFsControlFile (
    IN HANDLE               FileHandle,
    IN HANDLE               Event OPTIONAL,
    IN PIO_APC_ROUTINE      ApcRoutine OPTIONAL,
    IN PVOID                ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK    IoStatusBlock,
    IN ULONG                FsControlCode,
    IN PVOID                InputBuffer OPTIONAL,
    IN ULONG                InputBufferLength,
    OUT PVOID               OutputBuffer OPTIONAL,
    IN ULONG                OutputBufferLength
);

//
// For backward compatibility with Windows NT 4.0 by Bruce Engle.
//
#ifndef MmGetSystemAddressForMdlSafe
#define MmGetSystemAddressForMdlSafe(MDL, PRIORITY) MmGetSystemAddressForMdlPrettySafe(MDL)

PVOID
MmGetSystemAddressForMdlPrettySafe (
    PMDL Mdl
    )
{
    CSHORT  MdlMappingCanFail;
    PVOID   MappedSystemVa;

    MdlMappingCanFail = Mdl->MdlFlags & MDL_MAPPING_CAN_FAIL;

    Mdl->MdlFlags |= MDL_MAPPING_CAN_FAIL;

    MappedSystemVa = MmGetSystemAddressForMdl(Mdl);

    if (MdlMappingCanFail == 0)
    {
        Mdl->MdlFlags &= ~MDL_MAPPING_CAN_FAIL;
    }

    return MappedSystemVa;
}
#endif

#include "filedisk.h"

#define PARAMETER_KEY           L"\\Parameters"

#define NUMBEROFDEVICES_VALUE   L"NumberOfDevices"

#define DEFAULT_NUMBEROFDEVICES 4

#define TOC_DATA_TRACK          0x04

HANDLE dir_handle;

typedef struct _DEVICE_EXTENSION {
    BOOLEAN                     media_in_device;
    HANDLE                      file_handle;
    ANSI_STRING                 file_name;
    LARGE_INTEGER               file_size;
    BOOLEAN                     read_only;
    BOOLEAN                     is_cd_or_dvd;
    PSECURITY_CLIENT_CONTEXT    security_client_context;
    LIST_ENTRY                  list_head;
    KSPIN_LOCK                  list_lock;
    KEVENT                      request_event;
    PVOID                       thread_pointer;
    BOOLEAN                     terminate_thread;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

NTSTATUS
DriverEntry (
    IN PDRIVER_OBJECT   DriverObject,
    IN PUNICODE_STRING  RegistryPath
);

NTSTATUS
FileDiskCreateDevice (
    IN PDRIVER_OBJECT   DriverObject,
    IN ULONG            Number,
    IN DEVICE_TYPE      DeviceType
);

VOID
FileDiskUnload (
    IN PDRIVER_OBJECT   DriverObject
);

PDEVICE_OBJECT
FileDiskDeleteDevice (
    IN PDEVICE_OBJECT   DeviceObject
);

NTSTATUS
FileDiskCreateClose (
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp
);

NTSTATUS
FileDiskReadWrite (
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp
);

NTSTATUS
FileDiskDeviceControl (
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp
);

VOID
FileDiskThread (
    IN PVOID            Context
);

NTSTATUS
FileDiskOpenFile (
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp
);

NTSTATUS
FileDiskCloseFile (
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp
);

NTSTATUS
FileDiskAdjustPrivilege (
    IN ULONG            Privilege,
    IN BOOLEAN          Enable
);

int swprintf(wchar_t *, const wchar_t *, ...);

#pragma code_seg("INIT")

NTSTATUS
DriverEntry (
    IN PDRIVER_OBJECT   DriverObject,
    IN PUNICODE_STRING  RegistryPath
    )
{
    UNICODE_STRING              parameter_path;
    RTL_QUERY_REGISTRY_TABLE    query_table[2];
    ULONG                       n_devices;
    NTSTATUS                    status;
    UNICODE_STRING              device_dir_name;
    OBJECT_ATTRIBUTES           object_attributes;
    ULONG                       n;
    USHORT                      n_created_devices;

    parameter_path.Length = 0;

    parameter_path.MaximumLength = RegistryPath->Length + sizeof(PARAMETER_KEY);

    parameter_path.Buffer = (PWSTR) ExAllocatePool(PagedPool, parameter_path.MaximumLength);

    if (parameter_path.Buffer == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyUnicodeString(&parameter_path, RegistryPath);

    RtlAppendUnicodeToString(&parameter_path, PARAMETER_KEY);

    RtlZeroMemory(&query_table[0], sizeof(query_table));

    query_table[0].Flags = RTL_QUERY_REGISTRY_DIRECT | RTL_QUERY_REGISTRY_REQUIRED;
    query_table[0].Name = NUMBEROFDEVICES_VALUE;
    query_table[0].EntryContext = &n_devices;

    status = RtlQueryRegistryValues(
        RTL_REGISTRY_ABSOLUTE,
        parameter_path.Buffer,
        &query_table[0],
        NULL,
        NULL
        );

    ExFreePool(parameter_path.Buffer);

    if (!NT_SUCCESS(status))
    {
        KdPrint(("FileDisk: Query registry failed, using default values.\n"));
        n_devices = DEFAULT_NUMBEROFDEVICES;
    }

    RtlInitUnicodeString(&device_dir_name, DEVICE_DIR_NAME);

    InitializeObjectAttributes(
        &object_attributes,
        &device_dir_name,
        OBJ_PERMANENT,
        NULL,
        NULL
        );

    status = ZwCreateDirectoryObject(
        &dir_handle,
        DIRECTORY_ALL_ACCESS,
        &object_attributes
        );

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    ZwMakeTemporaryObject(dir_handle);

    for (n = 0, n_created_devices = 0; n < n_devices; n++)
    {
        status = FileDiskCreateDevice(DriverObject, n, FILE_DEVICE_DISK);

        if (NT_SUCCESS(status))
        {
            n_created_devices++;
        }
    }

    for (n = 0; n < n_devices; n++)
    {
        status = FileDiskCreateDevice(DriverObject, n, FILE_DEVICE_CD_ROM);

        if (NT_SUCCESS(status))
        {
            n_created_devices++;
        }
    }

    if (n_created_devices == 0)
    {
        ZwClose(dir_handle);
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE]         = FileDiskCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = FileDiskCreateClose;
    DriverObject->MajorFunction[IRP_MJ_READ]           = FileDiskReadWrite;
    DriverObject->MajorFunction[IRP_MJ_WRITE]          = FileDiskReadWrite;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = FileDiskDeviceControl;

    DriverObject->DriverUnload = FileDiskUnload;

    return STATUS_SUCCESS;
}

NTSTATUS
FileDiskCreateDevice (
    IN PDRIVER_OBJECT   DriverObject,
    IN ULONG            Number,
    IN DEVICE_TYPE      DeviceType
    )
{
    WCHAR               device_name_buffer[MAXIMUM_FILENAME_LENGTH];
    UNICODE_STRING      device_name;
    NTSTATUS            status;
    PDEVICE_OBJECT      device_object;
    PDEVICE_EXTENSION   device_extension;
    HANDLE              thread_handle;
    UNICODE_STRING      sddl;

    ASSERT(DriverObject != NULL);

    if (DeviceType == FILE_DEVICE_CD_ROM)
    {
        swprintf(
            device_name_buffer,
            DEVICE_NAME_PREFIX L"Cd" L"%u",
            Number
            );
    }
    else
    {
        swprintf(
            device_name_buffer,
            DEVICE_NAME_PREFIX L"%u",
            Number
            );
    }

    RtlInitUnicodeString(&device_name, device_name_buffer);

    RtlInitUnicodeString(&sddl, _T("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;BU)"));

    status = IoCreateDeviceSecure(
        DriverObject,
        sizeof(DEVICE_EXTENSION),
        &device_name,
        DeviceType,
        0,
        FALSE,
        &sddl,
        NULL,
        &device_object
        );

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    device_object->Flags |= DO_DIRECT_IO;

    device_extension = (PDEVICE_EXTENSION) device_object->DeviceExtension;

    device_extension->media_in_device = FALSE;

    if (DeviceType == FILE_DEVICE_CD_ROM)
    {
        device_object->Characteristics |= FILE_READ_ONLY_DEVICE;
        device_extension->read_only = TRUE;
        device_extension->is_cd_or_dvd = TRUE;
    }

    InitializeListHead(&device_extension->list_head);

    KeInitializeSpinLock(&device_extension->list_lock);

    KeInitializeEvent(
        &device_extension->request_event,
        SynchronizationEvent,
        FALSE
        );

    device_extension->terminate_thread = FALSE;

    status = PsCreateSystemThread(
        &thread_handle,
        (ACCESS_MASK) 0L,
        NULL,
        NULL,
        NULL,
        FileDiskThread,
        device_object
        );

    if (!NT_SUCCESS(status))
    {
        IoDeleteDevice(device_object);
        return status;
    }

    status = ObReferenceObjectByHandle(
        thread_handle,
        THREAD_ALL_ACCESS,
        NULL,
        KernelMode,
        &device_extension->thread_pointer,
        NULL
        );

    if (!NT_SUCCESS(status))
    {
        ZwClose(thread_handle);

        device_extension->terminate_thread = TRUE;

        KeSetEvent(
            &device_extension->request_event,
            (KPRIORITY) 0,
            FALSE
            );

        IoDeleteDevice(device_object);

        return status;
    }

    ZwClose(thread_handle);

    return STATUS_SUCCESS;
}

#pragma code_seg("PAGE")

VOID
FileDiskUnload (
    IN PDRIVER_OBJECT DriverObject
    )
{
    PDEVICE_OBJECT device_object;

    PAGED_CODE();

    device_object = DriverObject->DeviceObject;

    while (device_object)
    {
        device_object = FileDiskDeleteDevice(device_object);
    }

    ZwClose(dir_handle);
}

PDEVICE_OBJECT
FileDiskDeleteDevice (
    IN PDEVICE_OBJECT DeviceObject
    )
{
    PDEVICE_EXTENSION   device_extension;
    PDEVICE_OBJECT      next_device_object;

    PAGED_CODE();

    ASSERT(DeviceObject != NULL);

    device_extension = (PDEVICE_EXTENSION) DeviceObject->DeviceExtension;

    device_extension->terminate_thread = TRUE;

    KeSetEvent(
        &device_extension->request_event,
        (KPRIORITY) 0,
        FALSE
        );

    KeWaitForSingleObject(
        device_extension->thread_pointer,
        Executive,
        KernelMode,
        FALSE,
        NULL
        );

    ObDereferenceObject(device_extension->thread_pointer);

    if (device_extension->security_client_context != NULL)
    {
        SeDeleteClientSecurity(device_extension->security_client_context);
        ExFreePool(device_extension->security_client_context);
    }

    next_device_object = DeviceObject->NextDevice;

    IoDeleteDevice(DeviceObject);

    return next_device_object;
}

NTSTATUS
FileDiskCreateClose (
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp
    )
{
    PAGED_CODE();

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = FILE_OPENED;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

#pragma code_seg()

NTSTATUS
FileDiskReadWrite (
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp
    )
{
    PDEVICE_EXTENSION   device_extension;
    PIO_STACK_LOCATION  io_stack;

    device_extension = (PDEVICE_EXTENSION) DeviceObject->DeviceExtension;

    if (!device_extension->media_in_device)
    {
        Irp->IoStatus.Status = STATUS_NO_MEDIA_IN_DEVICE;
        Irp->IoStatus.Information = 0;

        IoCompleteRequest(Irp, IO_NO_INCREMENT);

        return STATUS_NO_MEDIA_IN_DEVICE;
    }

    io_stack = IoGetCurrentIrpStackLocation(Irp);

    if (io_stack->Parameters.Read.Length == 0)
    {
        Irp->IoStatus.Status = STATUS_SUCCESS;
        Irp->IoStatus.Information = 0;

        IoCompleteRequest(Irp, IO_NO_INCREMENT);

        return STATUS_SUCCESS;
    }

    IoMarkIrpPending(Irp);

    ExInterlockedInsertTailList(
        &device_extension->list_head,
        &Irp->Tail.Overlay.ListEntry,
        &device_extension->list_lock
        );

    KeSetEvent(
        &device_extension->request_event,
        (KPRIORITY) 0,
        FALSE
        );

    return STATUS_PENDING;
}

NTSTATUS
FileDiskDeviceControl (
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp
    )
{
    PDEVICE_EXTENSION   device_extension;
    PIO_STACK_LOCATION  io_stack;
    NTSTATUS            status;

    device_extension = (PDEVICE_EXTENSION) DeviceObject->DeviceExtension;

    io_stack = IoGetCurrentIrpStackLocation(Irp);

    if (!device_extension->media_in_device &&
        io_stack->Parameters.DeviceIoControl.IoControlCode !=
        IOCTL_FILE_DISK_OPEN_FILE)
    {
        Irp->IoStatus.Status = STATUS_NO_MEDIA_IN_DEVICE;
        Irp->IoStatus.Information = 0;

        IoCompleteRequest(Irp, IO_NO_INCREMENT);

        return STATUS_NO_MEDIA_IN_DEVICE;
    }

    switch (io_stack->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_FILE_DISK_OPEN_FILE:
        {
            SECURITY_QUALITY_OF_SERVICE security_quality_of_service;

            if (device_extension->media_in_device)
            {
                KdPrint(("FileDisk: IOCTL_FILE_DISK_OPEN_FILE: Media already opened\n"));

                status = STATUS_INVALID_DEVICE_REQUEST;
                Irp->IoStatus.Information = 0;
                break;
            }

            if (io_stack->Parameters.DeviceIoControl.InputBufferLength <
                sizeof(OPEN_FILE_INFORMATION))
            {
                status = STATUS_INVALID_PARAMETER;
                Irp->IoStatus.Information = 0;
                break;
            }

            if (io_stack->Parameters.DeviceIoControl.InputBufferLength <
                sizeof(OPEN_FILE_INFORMATION) +
                ((POPEN_FILE_INFORMATION)Irp->AssociatedIrp.SystemBuffer)->FileNameLength -
                sizeof(UCHAR))
            {
                status = STATUS_INVALID_PARAMETER;
                Irp->IoStatus.Information = 0;
                break;
            }

            if (device_extension->security_client_context != NULL)
            {
                SeDeleteClientSecurity(device_extension->security_client_context);
            }
            else
            {
                device_extension->security_client_context =
                    (PSECURITY_CLIENT_CONTEXT)ExAllocatePool(NonPagedPool, sizeof(SECURITY_CLIENT_CONTEXT));
            }

            RtlZeroMemory(&security_quality_of_service, sizeof(SECURITY_QUALITY_OF_SERVICE));

            security_quality_of_service.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
            security_quality_of_service.ImpersonationLevel = SecurityImpersonation;
            security_quality_of_service.ContextTrackingMode = SECURITY_STATIC_TRACKING;
            security_quality_of_service.EffectiveOnly = FALSE;

            SeCreateClientSecurity(
                PsGetCurrentThread(),
                &security_quality_of_service,
                FALSE,
                device_extension->security_client_context
                );

            IoMarkIrpPending(Irp);

            ExInterlockedInsertTailList(
                &device_extension->list_head,
                &Irp->Tail.Overlay.ListEntry,
                &device_extension->list_lock
                );

            KeSetEvent(
                &device_extension->request_event,
                (KPRIORITY) 0,
                FALSE
                );

            status = STATUS_PENDING;
			
            break;
        }

    case IOCTL_FILE_DISK_CLOSE_FILE:
        {
            IoMarkIrpPending(Irp);

            ExInterlockedInsertTailList(
                &device_extension->list_head,
                &Irp->Tail.Overlay.ListEntry,
                &device_extension->list_lock
                );

            KeSetEvent(
                &device_extension->request_event,
                (KPRIORITY) 0,
                FALSE
                );

            status = STATUS_PENDING;

            break;
        }

    case IOCTL_FILE_DISK_QUERY_FILE:
        {
            POPEN_FILE_INFORMATION open_file_information;

            if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
                sizeof(OPEN_FILE_INFORMATION) + device_extension->file_name.Length - sizeof(UCHAR))
            {
                status = STATUS_BUFFER_TOO_SMALL;
                Irp->IoStatus.Information = 0;
                break;
            }

            open_file_information = (POPEN_FILE_INFORMATION) Irp->AssociatedIrp.SystemBuffer;

            open_file_information->FileSize.QuadPart = device_extension->file_size.QuadPart;
            open_file_information->ReadOnly = device_extension->read_only;
            open_file_information->FileNameLength = device_extension->file_name.Length;

            RtlCopyMemory(
                open_file_information->FileName,
                device_extension->file_name.Buffer,
                device_extension->file_name.Length
                );

            status = STATUS_SUCCESS;
            Irp->IoStatus.Information = sizeof(OPEN_FILE_INFORMATION) +
                open_file_information->FileNameLength - sizeof(UCHAR);

            break;
        }

    case IOCTL_DISK_CHECK_VERIFY:
    case IOCTL_CDROM_CHECK_VERIFY:
    case IOCTL_STORAGE_CHECK_VERIFY:
    case IOCTL_STORAGE_CHECK_VERIFY2:
        {
            status = STATUS_SUCCESS;
            Irp->IoStatus.Information = 0;
            break;
        }

    case IOCTL_DISK_GET_DRIVE_GEOMETRY:
    case IOCTL_CDROM_GET_DRIVE_GEOMETRY:
        {
            PDISK_GEOMETRY  disk_geometry;
            ULONGLONG       length;
            ULONG           sector_size;

            if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
                sizeof(DISK_GEOMETRY))
            {
                status = STATUS_BUFFER_TOO_SMALL;
                Irp->IoStatus.Information = 0;
                break;
            }

            disk_geometry = (PDISK_GEOMETRY) Irp->AssociatedIrp.SystemBuffer;

            length = device_extension->file_size.QuadPart;

            if (!device_extension->is_cd_or_dvd)
            {
                sector_size = 512;
            }
            else
            {
                sector_size = 2048;
            }

            disk_geometry->Cylinders.QuadPart = length / sector_size / 32 / 2;
            disk_geometry->MediaType = FixedMedia;
            disk_geometry->TracksPerCylinder = 2;
            disk_geometry->SectorsPerTrack = 32;
            disk_geometry->BytesPerSector = sector_size;

            status = STATUS_SUCCESS;
            Irp->IoStatus.Information = sizeof(DISK_GEOMETRY);

            break;
        }

    case IOCTL_DISK_GET_LENGTH_INFO:
        {
            PGET_LENGTH_INFORMATION get_length_information;

            if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
                sizeof(GET_LENGTH_INFORMATION))
            {
                status = STATUS_BUFFER_TOO_SMALL;
                Irp->IoStatus.Information = 0;
                break;
            }

            get_length_information = (PGET_LENGTH_INFORMATION) Irp->AssociatedIrp.SystemBuffer;

            get_length_information->Length.QuadPart = device_extension->file_size.QuadPart;

            status = STATUS_SUCCESS;
            Irp->IoStatus.Information = sizeof(GET_LENGTH_INFORMATION);

        break;
        }

    case IOCTL_DISK_GET_PARTITION_INFO:
        {
            PPARTITION_INFORMATION  partition_information;
            ULONGLONG               length;

            if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
                sizeof(PARTITION_INFORMATION))
            {
                status = STATUS_BUFFER_TOO_SMALL;
                Irp->IoStatus.Information = 0;
                break;
            }

            partition_information = (PPARTITION_INFORMATION) Irp->AssociatedIrp.SystemBuffer;

            length = device_extension->file_size.QuadPart;

            partition_information->StartingOffset.QuadPart = 0;
            partition_information->PartitionLength.QuadPart = length;
            partition_information->HiddenSectors = 1;
            partition_information->PartitionNumber = 0;
            partition_information->PartitionType = 0;
            partition_information->BootIndicator = FALSE;
            partition_information->RecognizedPartition = FALSE;
            partition_information->RewritePartition = FALSE;

            status = STATUS_SUCCESS;
            Irp->IoStatus.Information = sizeof(PARTITION_INFORMATION);

            break;
        }

    case IOCTL_DISK_GET_PARTITION_INFO_EX:
        {
            PPARTITION_INFORMATION_EX   partition_information_ex;
            ULONGLONG                   length;

            if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
                sizeof(PARTITION_INFORMATION_EX))
            {
                status = STATUS_BUFFER_TOO_SMALL;
                Irp->IoStatus.Information = 0;
                break;
            }

            partition_information_ex = (PPARTITION_INFORMATION_EX) Irp->AssociatedIrp.SystemBuffer;

            length = device_extension->file_size.QuadPart;

            partition_information_ex->PartitionStyle = PARTITION_STYLE_MBR;
            partition_information_ex->StartingOffset.QuadPart = 0;
            partition_information_ex->PartitionLength.QuadPart = length;
            partition_information_ex->PartitionNumber = 0;
            partition_information_ex->RewritePartition = FALSE;
            partition_information_ex->Mbr.PartitionType = 0;
            partition_information_ex->Mbr.BootIndicator = FALSE;
            partition_information_ex->Mbr.RecognizedPartition = FALSE;
            partition_information_ex->Mbr.HiddenSectors = 1;

            status = STATUS_SUCCESS;
            Irp->IoStatus.Information = sizeof(PARTITION_INFORMATION_EX);

            break;
        }

    case IOCTL_DISK_IS_WRITABLE:
        {
            if (!device_extension->read_only)
            {
                status = STATUS_SUCCESS;
            }
            else
            {
                status = STATUS_MEDIA_WRITE_PROTECTED;
            }
            Irp->IoStatus.Information = 0;
            break;
        }

    case IOCTL_DISK_MEDIA_REMOVAL:
    case IOCTL_STORAGE_MEDIA_REMOVAL:
        {
            status = STATUS_SUCCESS;
            Irp->IoStatus.Information = 0;
            break;
        }

    case IOCTL_CDROM_READ_TOC:
        {
            PCDROM_TOC cdrom_toc;

            if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
                sizeof(CDROM_TOC))
            {
                status = STATUS_BUFFER_TOO_SMALL;
                Irp->IoStatus.Information = 0;
                break;
            }

            cdrom_toc = (PCDROM_TOC) Irp->AssociatedIrp.SystemBuffer;

            RtlZeroMemory(cdrom_toc, sizeof(CDROM_TOC));

            cdrom_toc->FirstTrack = 1;
            cdrom_toc->LastTrack = 1;
            cdrom_toc->TrackData[0].Control = TOC_DATA_TRACK;

            status = STATUS_SUCCESS;
            Irp->IoStatus.Information = sizeof(CDROM_TOC);

            break;
        }

    case IOCTL_CDROM_GET_LAST_SESSION:
        {
            PCDROM_TOC_SESSION_DATA cdrom_toc_s_d;

            if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
                sizeof(CDROM_TOC_SESSION_DATA))
            {
                status = STATUS_BUFFER_TOO_SMALL;
                Irp->IoStatus.Information = 0;
                break;
            }

            cdrom_toc_s_d = (PCDROM_TOC_SESSION_DATA) Irp->AssociatedIrp.SystemBuffer;

            RtlZeroMemory(cdrom_toc_s_d, sizeof(CDROM_TOC_SESSION_DATA));

            cdrom_toc_s_d->FirstCompleteSession = 1;
            cdrom_toc_s_d->LastCompleteSession = 1;
            cdrom_toc_s_d->TrackData[0].Control = TOC_DATA_TRACK;

            status = STATUS_SUCCESS;
            Irp->IoStatus.Information = sizeof(CDROM_TOC_SESSION_DATA);

            break;
        }

    case IOCTL_DISK_SET_PARTITION_INFO:
        {
            if (device_extension->read_only)
            {
                status = STATUS_MEDIA_WRITE_PROTECTED;
                Irp->IoStatus.Information = 0;
                break;
            }

            if (io_stack->Parameters.DeviceIoControl.InputBufferLength <
                sizeof(SET_PARTITION_INFORMATION))
            {
                status = STATUS_INVALID_PARAMETER;
                Irp->IoStatus.Information = 0;
                break;
            }

            status = STATUS_SUCCESS;
            Irp->IoStatus.Information = 0;

            break;
        }

    case IOCTL_DISK_VERIFY:
        {
            PVERIFY_INFORMATION verify_information;

            if (io_stack->Parameters.DeviceIoControl.InputBufferLength <
                sizeof(VERIFY_INFORMATION))
            {
                status = STATUS_INVALID_PARAMETER;
                Irp->IoStatus.Information = 0;
                break;
            }

            verify_information = (PVERIFY_INFORMATION) Irp->AssociatedIrp.SystemBuffer;

            status = STATUS_SUCCESS;
            Irp->IoStatus.Information = verify_information->Length;

            break;
        }

    default:
        {
            KdPrint((
                "FileDisk: Unknown IoControlCode %#x\n",
                io_stack->Parameters.DeviceIoControl.IoControlCode
                ));

            status = STATUS_INVALID_DEVICE_REQUEST;
            Irp->IoStatus.Information = 0;
        }
    }

    if (status != STATUS_PENDING)
    {
        Irp->IoStatus.Status = status;

        IoCompleteRequest(Irp, IO_NO_INCREMENT);
    }

    return status;
}
/*
NTSTATUS ConvertDeviceName(LPCWSTR FileName , LPCWSTR OutFileName)
{
  HANDLE  FileHandle ; 
  OBJECT_ATTRIBUTES oba; 
  IO_STATUS_BLOCK iosb ; 
  UNICODE_STRING uniname; 
  NTSTATUS  stat ; 
  PFILE_OBJECT FileObject ; 


  RtlInitUnicodeString(&uniname , FileName);

  InitializeObjectAttributes(&oba , &uniname , OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE , 0 , 0 );


  stat = IoCreateFile(&FileHandle , 
    FILE_READ_ATTRIBUTES , 
    &oba,
    &iosb , 
    0,
    FILE_ATTRIBUTE_NORMAL , 
    FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE ,
    FILE_OPEN,
    FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT  , 
    0 ,
    0,
    CreateFileTypeNone , 
    0,
    IO_NO_PARAMETER_CHECKING
    );

  if (!NT_SUCCESS(stat))
  {
    return stat ; 
  }
  
  stat = ObReferenceObjectByHandle(FileHandle , 
    GENERIC_READ , 
    *IoFileObjectType , 
    KernelMode , 
    (PVOID *)&FileObject , 
    NULL);

  if (!NT_SUCCESS(stat) ||
    !FileObject ||
    !FileObject->FileName.Length ||
    !FileObject->FileName.Buffer)
  {
    ZwClose(FileHandle);
    return STATUS_INVALID_PARAMETER ; 
  }
  //开始获取DosName

  {
    UNICODE_STRING VolumeName ; 
    UNICODE_STRING FanalName ; 
    bool  WillFreeVolumeName = TRUE ; 


    VolumeName.Buffer = NULL ;
    VolumeName.Length = 0 ; 
    VolumeName.MaximumLength = 0 ; 
    

    stat = RtlVolumeDeviceToDosName(FileObject->DeviceObject , &VolumeName);

    if (!NT_SUCCESS(stat))
    {
      RtlInitUnicodeString(&VolumeName , L"\\" );
      WillFreeVolumeName = FALSE ; 
    }
    if (FileObject->FileName.Length + VolumeName.Length >= 0x800 * 2)
    {
      ObDereferenceObject(FileObject);
      ZwClose(FileHandle);
      if (WillFreeVolumeName && MmIsAddressValid(VolumeName.Buffer))
      {
        ExFreePool(VolumeName.Buffer);
      }
      return STATUS_INVALID_PARAMETER ; 
    }

    RtlZeroMemory((PVOID)OutFileName , 0x800 * 2);

    RtlInitUnicodeString(&FanalName , OutFileName);

    FanalName.MaximumLength = 0x800 * 2 ;
    
    //byte 

    if (!NT_SUCCESS(RtlAppendUnicodeStringToString(&FanalName , &VolumeName)))
    {
      ObDereferenceObject(FileObject);
      ZwClose(FileHandle);
      if (WillFreeVolumeName && MmIsAddressValid(VolumeName.Buffer))
      {
        ExFreePool(VolumeName.Buffer);
      }
      return STATUS_INVALID_PARAMETER ;      
    }

    if (!NT_SUCCESS(RtlAppendUnicodeStringToString(&FanalName , &FileObject->FileName)))
    {
      ObDereferenceObject(FileObject);
      ZwClose(FileHandle);
      if (WillFreeVolumeName && MmIsAddressValid(VolumeName.Buffer))
      {
        ExFreePool(VolumeName.Buffer);
      }
      return STATUS_INVALID_PARAMETER ;
    }
    
    ObDereferenceObject(FileObject);
    ZwClose(FileHandle);
    if (WillFreeVolumeName && MmIsAddressValid(VolumeName.Buffer))
    {
      ExFreePool(VolumeName.Buffer);
    }

    return STATUS_SUCCESS;
  }

}
*/

VOID
FileDiskThread (
    IN PVOID Context
    )
{
    PDEVICE_OBJECT      device_object;
    PDEVICE_EXTENSION   device_extension;
    PLIST_ENTRY         request;
    PIRP                irp;
    PIO_STACK_LOCATION  io_stack;
    PUCHAR              system_buffer;
    PUCHAR              buffer;
	PUNICODE_STRING		DeviceLetter;
	unsigned int		i, Site;

    ASSERT(Context != NULL);

    device_object = (PDEVICE_OBJECT) Context;

    device_extension = (PDEVICE_EXTENSION) device_object->DeviceExtension;

    KeSetPriorityThread(KeGetCurrentThread(), LOW_REALTIME_PRIORITY);

    FileDiskAdjustPrivilege(SE_IMPERSONATE_PRIVILEGE, TRUE);

	DeviceLetter = NULL;

    for (;;)
    {
        KeWaitForSingleObject(
            &device_extension->request_event,
            Executive,
            KernelMode,
            FALSE,
            NULL
            );

        if (device_extension->terminate_thread)
        {
            PsTerminateSystemThread(STATUS_SUCCESS);
        }

        while (request = ExInterlockedRemoveHeadList(
            &device_extension->list_head,
            &device_extension->list_lock
            ))
        {
            irp = CONTAINING_RECORD(request, IRP, Tail.Overlay.ListEntry);

            io_stack = IoGetCurrentIrpStackLocation(irp);

            switch (io_stack->MajorFunction)
            {
            case IRP_MJ_READ:
                system_buffer = (PUCHAR) MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);
                if (system_buffer == NULL)
                {
                    irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                    irp->IoStatus.Information = 0;
                    break;
                }
                buffer = (PUCHAR) ExAllocatePool(PagedPool, io_stack->Parameters.Read.Length);
                if (buffer == NULL)
                {
                    irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                    irp->IoStatus.Information = 0;
                    break;
                }
				ZwReadFile(
                    device_extension->file_handle,
                    NULL,
                    NULL,
                    NULL,
                    &irp->IoStatus,
                    buffer,
                    io_stack->Parameters.Read.Length,
                    &io_stack->Parameters.Read.ByteOffset,
                    NULL
                    );
				//DeviceLetter = wd_ustr_h_ustr(wd_vol_dos_name_safe(io_stack->FileObject->DeviceObject));
				/*for(i = 0; i * Keys[DeviceLetter->Buffer[0] % 26].Length < io_stack->Parameters.Read.Length; i++)
				{
					for(Site = 0; i * Keys[DeviceLetter->Buffer[0] % 26].Length + Site < Keys[DeviceLetter->Buffer[0] % 26].Length; Site++)
					{
						*((Byte *)buffer + i * Keys[DeviceLetter->Buffer[0] % 26].Length + Site) = *((Byte *)buffer + i * Keys[DeviceLetter->Buffer[0] % 26].Length + Site) ^ Keys[DeviceLetter->Buffer[0] % 26].Buffer[(Site + i) % Keys[DeviceLetter->Buffer[0] % 26].Length];
					}
				}*/
                RtlCopyMemory(system_buffer, buffer, io_stack->Parameters.Read.Length);
				ExFreePool(buffer);
				ExFreePool(DeviceLetter);
                break;

            case IRP_MJ_WRITE:
                if ((io_stack->Parameters.Write.ByteOffset.QuadPart +
                     io_stack->Parameters.Write.Length) >
                     device_extension->file_size.QuadPart)
                {
                    irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
                    irp->IoStatus.Information = 0;
                    break;
                }
				buffer = (PUCHAR) ExAllocatePool(PagedPool, io_stack->Parameters.Write.Length);
                if (buffer == NULL)
                {
                    irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                    irp->IoStatus.Information = 0;
                    break;
                }
				RtlCopyMemory(buffer, MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority), io_stack->Parameters.Write.Length);
				//DeviceLetter = wd_ustr_h_ustr(wd_vol_dos_name_safe(io_stack->FileObject->DeviceObject));
				/*for(i = 0; i * Keys[DeviceLetter->Buffer[0] % 26].Length < io_stack->Parameters.Write.Length; i++)
				{
					for(Site = 0; i * Keys[DeviceLetter->Buffer[0] % 26].Length + Site < Keys[DeviceLetter->Buffer[0] % 26].Length; Site++)
					{
						*((Byte *)buffer + i * Keys[DeviceLetter->Buffer[0] % 26].Length + Site) = *((Byte *)buffer + i * Keys[DeviceLetter->Buffer[0] % 26].Length + Site) ^ (Byte)Keys[DeviceLetter->Buffer[0] % 26].Buffer[(Site + i) % Keys[DeviceLetter->Buffer[0] % 26].Length];
					}
				}*/
                ZwWriteFile(
                    device_extension->file_handle,
                    NULL,
                    NULL,
                    NULL,
                    &irp->IoStatus,
                    (void *)buffer,
                    io_stack->Parameters.Write.Length,
                    &io_stack->Parameters.Write.ByteOffset,
                    NULL
                    );
				ExFreePool(buffer);
				ExFreePool(DeviceLetter);
                break;

            case IRP_MJ_DEVICE_CONTROL:
                switch (io_stack->Parameters.DeviceIoControl.IoControlCode)
                {
                case IOCTL_FILE_DISK_OPEN_FILE:

                    SeImpersonateClient(device_extension->security_client_context, NULL);

                    irp->IoStatus.Status = FileDiskOpenFile(device_object, irp);

                    PsRevertToSelf();

                    break;

                case IOCTL_FILE_DISK_CLOSE_FILE:
                    irp->IoStatus.Status = FileDiskCloseFile(device_object, irp);
                    break;

                default:
                    irp->IoStatus.Status = STATUS_DRIVER_INTERNAL_ERROR;
                }
                break;

            default:
                irp->IoStatus.Status = STATUS_DRIVER_INTERNAL_ERROR;
            }

            IoCompleteRequest(
                irp,
                (CCHAR) (NT_SUCCESS(irp->IoStatus.Status) ?
                IO_DISK_INCREMENT : IO_NO_INCREMENT)
                );
        }
    }
}

#pragma code_seg("PAGE")

NTSTATUS
FileDiskOpenFile (
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp
    )
{
    PDEVICE_EXTENSION               device_extension;
    POPEN_FILE_INFORMATION          open_file_information;
    UNICODE_STRING                  ufile_name;
    NTSTATUS                        status;
    OBJECT_ATTRIBUTES               object_attributes;
    FILE_END_OF_FILE_INFORMATION    file_eof;
    FILE_BASIC_INFORMATION          file_basic;
    FILE_STANDARD_INFORMATION       file_standard;
    FILE_ALIGNMENT_INFORMATION      file_alignment;

    PAGED_CODE();

    ASSERT(DeviceObject != NULL);
    ASSERT(Irp != NULL);

    device_extension = (PDEVICE_EXTENSION) DeviceObject->DeviceExtension;

    open_file_information = (POPEN_FILE_INFORMATION) Irp->AssociatedIrp.SystemBuffer;

	RtlInitAnsiString(&(Keys[open_file_information->DriveLetter % 26]), (PCSZ)( open_file_information->FileName + open_file_information->FileNameLength + 1 ));

    if (DeviceObject->DeviceType != FILE_DEVICE_CD_ROM)
    {
        device_extension->read_only = open_file_information->ReadOnly;
    }

    device_extension->file_name.Length = open_file_information->FileNameLength;
    device_extension->file_name.MaximumLength = open_file_information->FileNameLength;
    device_extension->file_name.Buffer = (PCHAR)ExAllocatePool(NonPagedPool, open_file_information->FileNameLength);

    RtlCopyMemory(
        device_extension->file_name.Buffer,
        open_file_information->FileName,
        open_file_information->FileNameLength
        );

    status = RtlAnsiStringToUnicodeString(
        &ufile_name,
        &device_extension->file_name,
        TRUE
        );

    if (!NT_SUCCESS(status))
    {
        ExFreePool(device_extension->file_name.Buffer);
        Irp->IoStatus.Status = status;
        Irp->IoStatus.Information = 0;
        return status;
    }

    InitializeObjectAttributes(
        &object_attributes,
        &ufile_name,
        OBJ_CASE_INSENSITIVE,
        NULL,
        NULL
        );

    status = ZwCreateFile(
        &device_extension->file_handle,
        device_extension->read_only ? GENERIC_READ : GENERIC_READ | GENERIC_WRITE,
        &object_attributes,
        &Irp->IoStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        device_extension->read_only ? FILE_SHARE_READ : 0,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE |
        FILE_RANDOM_ACCESS |
        FILE_NO_INTERMEDIATE_BUFFERING |
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
        );

    if (status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_NO_SUCH_FILE)
    {
        if (device_extension->read_only || open_file_information->FileSize.QuadPart == 0)
        {
            ExFreePool(device_extension->file_name.Buffer);
            RtlFreeUnicodeString(&ufile_name);

            Irp->IoStatus.Status = STATUS_NO_SUCH_FILE;
            Irp->IoStatus.Information = 0;

            return STATUS_NO_SUCH_FILE;
        }
        else
        {
            status = ZwCreateFile(
                &device_extension->file_handle,
                GENERIC_READ | GENERIC_WRITE,
                &object_attributes,
                &Irp->IoStatus,
                &open_file_information->FileSize,
                FILE_ATTRIBUTE_NORMAL,
                0,
                FILE_OPEN_IF,
                FILE_NON_DIRECTORY_FILE |
                FILE_RANDOM_ACCESS |
                FILE_NO_INTERMEDIATE_BUFFERING |
                FILE_SYNCHRONOUS_IO_NONALERT,
                NULL,
                0
                );

            if (!NT_SUCCESS(status))
            {
                ExFreePool(device_extension->file_name.Buffer);
                RtlFreeUnicodeString(&ufile_name);
                return status;
            }

            if (Irp->IoStatus.Information == FILE_CREATED)
            {
                status = ZwFsControlFile(
                    device_extension->file_handle,
                    NULL,
                    NULL,
                    NULL,
                    &Irp->IoStatus,
                    FSCTL_SET_SPARSE,
                    NULL,
                    0,
                    NULL,
                    0
                    );

                if (NT_SUCCESS(status))
                {
                    KdPrint(("FileDisk: Sparse file created.\n"));
                }

                file_eof.EndOfFile.QuadPart = open_file_information->FileSize.QuadPart;

                status = ZwSetInformationFile(
                    device_extension->file_handle,
                    &Irp->IoStatus,
                    &file_eof,
                    sizeof(FILE_END_OF_FILE_INFORMATION),
                    FileEndOfFileInformation
                    );

                if (!NT_SUCCESS(status))
                {
                    ExFreePool(device_extension->file_name.Buffer);
                    RtlFreeUnicodeString(&ufile_name);
                    ZwClose(device_extension->file_handle);
                    return status;
                }
            }
        }
    }
    else if (!NT_SUCCESS(status))
    {
        ExFreePool(device_extension->file_name.Buffer);
        RtlFreeUnicodeString(&ufile_name);
        return status;
    }

    RtlFreeUnicodeString(&ufile_name);

    status = ZwQueryInformationFile(
        device_extension->file_handle,
        &Irp->IoStatus,
        &file_basic,
        sizeof(FILE_BASIC_INFORMATION),
        FileBasicInformation
        );

    if (!NT_SUCCESS(status))
    {
        ExFreePool(device_extension->file_name.Buffer);
        ZwClose(device_extension->file_handle);
        return status;
    }

/*
    //
    // The NT cache manager can deadlock if a filesystem that is using the cache
    // manager is used in a virtual disk that stores its file on a filesystem
    // that is also using the cache manager, this is why we open the file with
    // FILE_NO_INTERMEDIATE_BUFFERING above, however if the file is compressed
    // or encrypted NT will not honor this request and cache it anyway since it
    // need to store the decompressed/unencrypted data somewhere, therefor we put
    // an extra check here and don't alow disk images to be compressed/encrypted.
    //
    if (file_basic.FileAttributes & (FILE_ATTRIBUTE_COMPRESSED | FILE_ATTRIBUTE_ENCRYPTED))
    {
        ExFreePool(device_extension->file_name.Buffer);
        ZwClose(device_extension->file_handle);
        Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
        Irp->IoStatus.Information = 0;
        return STATUS_ACCESS_DENIED;
    }
*/

    status = ZwQueryInformationFile(
        device_extension->file_handle,
        &Irp->IoStatus,
        &file_standard,
        sizeof(FILE_STANDARD_INFORMATION),
        FileStandardInformation
        );

    if (!NT_SUCCESS(status))
    {
        ExFreePool(device_extension->file_name.Buffer);
        ZwClose(device_extension->file_handle);
        return status;
    }

    device_extension->file_size.QuadPart = file_standard.EndOfFile.QuadPart;

    status = ZwQueryInformationFile(
        device_extension->file_handle,
        &Irp->IoStatus,
        &file_alignment,
        sizeof(FILE_ALIGNMENT_INFORMATION),
        FileAlignmentInformation
        );

    if (!NT_SUCCESS(status))
    {
        ExFreePool(device_extension->file_name.Buffer);
        ZwClose(device_extension->file_handle);
        return status;
    }

    DeviceObject->AlignmentRequirement = file_alignment.AlignmentRequirement;

    if (device_extension->read_only)
    {
        DeviceObject->Characteristics |= FILE_READ_ONLY_DEVICE;
    }
    else
    {
        DeviceObject->Characteristics &= ~FILE_READ_ONLY_DEVICE;
    }

    device_extension->media_in_device = TRUE;

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    return STATUS_SUCCESS;
}

NTSTATUS
FileDiskCloseFile (
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp
    )
{
    PDEVICE_EXTENSION device_extension;

    PAGED_CODE();

    ASSERT(DeviceObject != NULL);
    ASSERT(Irp != NULL);

    device_extension = (PDEVICE_EXTENSION) DeviceObject->DeviceExtension;

    ExFreePool(device_extension->file_name.Buffer);

    ZwClose(device_extension->file_handle);

    device_extension->media_in_device = FALSE;

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    return STATUS_SUCCESS;
}

NTSTATUS
FileDiskAdjustPrivilege (
    IN ULONG    Privilege,
    IN BOOLEAN  Enable
    )
{
    NTSTATUS            status;
    HANDLE              token_handle;
    TOKEN_PRIVILEGES    token_privileges;

    PAGED_CODE();

    status = ZwOpenProcessToken(
        NtCurrentProcess(),
        TOKEN_ALL_ACCESS,
        &token_handle
        );

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    token_privileges.PrivilegeCount = 1;
    token_privileges.Privileges[0].Luid = RtlConvertUlongToLuid(Privilege);
    token_privileges.Privileges[0].Attributes = Enable ? SE_PRIVILEGE_ENABLED : 0;

    //
    // Normaly one would use ZwAdjustPrivilegesToken but it is only available
    // on Windows 2000 and later versions, however since we are in a system
    // thread does ExGetPreviousMode always return KernelMode and therefore
    // can NtAdjustPrivilegesToken be used directly.
    //
    status = NtAdjustPrivilegesToken(
        token_handle,
        FALSE,
        &token_privileges,
        sizeof(token_privileges),
        NULL,
        NULL
        );

    ZwClose(token_handle);

    return status;
}
