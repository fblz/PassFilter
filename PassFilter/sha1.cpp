/*
* This code is adapted from:
* https://docs.microsoft.com/en-us/windows/win32/seccng/creating-a-hash-with-cng
*/

#include "pch.h"
#include "sha1.h"

// Defined in SubAuth.h
//#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)

#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)


int __cdecl sha1(
    char* data,
    int len,
    char* outbuf)
{

    BCRYPT_ALG_HANDLE       hAlg = NULL;
    BCRYPT_HASH_HANDLE      hHash = NULL;
    NTSTATUS                status = STATUS_UNSUCCESSFUL;
    DWORD                   cbData = 0,
        cbHash = 20,
        cbHashObject = 0;
    PBYTE                   pbHashObject = NULL;
    PBYTE                   pbHash = NULL;

    //open an algorithm handle
    if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_SHA1_ALGORITHM,
        NULL,
        0)))
    {
        goto Cleanup;
    }

    //calculate the size of the buffer to hold the hash object
    if (!NT_SUCCESS(status = BCryptGetProperty(
        hAlg,
        BCRYPT_OBJECT_LENGTH,
        (PBYTE)&cbHashObject,
        sizeof(DWORD),
        &cbData,
        0)))
    {
        goto Cleanup;
    }

    //allocate the hash object on the heap
    pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
    if (NULL == pbHashObject)
    {
        goto Cleanup;
    }


    //allocate the hash buffer on the heap
    pbHash = (PBYTE)outbuf;
    if (NULL == pbHash)
    {
        goto Cleanup;
    }

    //create a hash
    if (!NT_SUCCESS(status = BCryptCreateHash(
        hAlg,
        &hHash,
        pbHashObject,
        cbHashObject,
        NULL,
        0,
        0)))
    {
        goto Cleanup;
    }


    //hash some data
    if (!NT_SUCCESS(status = BCryptHashData(
        hHash,
        (PBYTE)data,
        len,
        0)))
    {
        goto Cleanup;
    }

    //close the hash
    if (!NT_SUCCESS(status = BCryptFinishHash(
        hHash,
        pbHash,
        cbHash,
        0)))
    {
        goto Cleanup;
    }
Cleanup:

    if (hAlg)
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }

    if (hHash)
    {
        BCryptDestroyHash(hHash);
    }

    if (pbHashObject)
    {
        HeapFree(GetProcessHeap(), 0, pbHashObject);
    }

    return status;

}