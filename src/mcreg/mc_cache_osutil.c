/* 
 * mc_cache_osutil.c
 * Copyright SilverSpring Networks 2018.
 * All rights reserved.
 *
 * OS specific functions for cert cache
 */

//#define UCOSII
#ifdef UCOSII

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "mcert_cache.h"
#include <mc_cache.h>
#include <ucos_ii.h>
#include "os_cfg.h"
#include <sysvar.h>
#include "assert.h"
#include <cert_cache.h>

OS_EVENT *mc_cache_lock;
#define MC_CACHE_MUTEX_PRI      6 //TODO: fix mutex pri value

error_t mc_lock(void);
error_t mc_unlock(void);


error_t mc_lock(void)
{
	uint8_t ret;
	OSMutexPend(mc_cache_lock, 0, &ret);
	if (ret != OS_ERR_NONE){
		MC_ERR("Error mc cache lock: %d\n", ret);
		return ERR_MC_CACHE_LOCK_ERROR;
	}
	return ERR_OK;
}

error_t mc_unlock(void)
{
	uint8_t ret;
	ret = OSMutexPost(mc_cache_lock);
	if (ret != OS_ERR_NONE){
		MC_ERR("Error mc cache unlock: %d\n", ret);
		return ERR_MC_CACHE_UNLOCK_ERROR;
	}
	return ERR_OK;
}

uint8_t mc_mutex_init()
{
	uint8_t ret;
	mc_cache_lock = OSMutexCreate(MC_CACHE_MUTEX_PRI,&ret);
return ret;
}

/**
 * uninit mcert cache
 * @return standard error codes
 */
error_t mc_cache_uninit()
{
	uint8_t ret;
	OS_EVENT *ret_mutex;
	ret_mutex = OSMutexDel(mc_cache_lock,OS_DEL_NO_PEND,&ret);
	if (ret_mutex != NULL)
	{
		MC_ERR("mcert cache mutex destroy failed. error %d\n",ret);
		return ERR_MC_CACHE_GEN_ERROR;
	}

	return ERR_OK;
}
#endif

#ifdef LINUX
#include <stdio.h>
#include <pthread.h>
#include <stdint.h>
#include <mc_cache.h>
//#include <exp_errors.h>

pthread_mutex_t mc_cache_lock;

error_t mc_lock(void){
	int ret;
	ret = pthread_mutex_lock(&mc_cache_lock);
	if (ret) {
		MC_ERR("Error mc cache lock: %d\n", ret);
		return ERR_MC_CACHE_LOCK_ERROR;
	}
	return ERR_OK;
}

error_t mc_unlock(void){
	int ret;
	ret = pthread_mutex_unlock(&mc_cache_lock);
	if (ret) {
		MC_ERR("Error mc cache unlock: %d\n", ret);
		return ERR_MC_CACHE_UNLOCK_ERROR;
	}
	return ERR_OK;
}

uint8_t mc_mutex_init()
{
	uint8_t ret;
	ret = pthread_mutex_init(&mc_cache_lock, NULL);
	if (ret != 0)
	{
		MC_ERR("mcert cache mutex init failed. error %d\n",ret);
		return ERR_MC_CACHE_GEN_ERROR;
	}
	return ret;
}

error_t mc_cache_uninit()
{
	int ret;

	ret = pthread_mutex_destroy(&mc_cache_lock);
	if (ret != 0)
	{
		MC_ERR("mcert cache mutex destroy failed. error %d\n",ret);
		return ERR_MC_CACHE_GEN_ERROR;
	}
	return ERR_OK;
}

#endif
