/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * KVM/MIPS: MIPS specific KVM APIs
 *
 * Copyright (C) 2012  MIPS Technologies, Inc.  All rights reserved.
 * Authors: Sanjay Lal <sanjayl@kymasys.com>
*/

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include <linux/kvm.h>

#include "qemu-common.h"
#include "qemu/timer.h"
#include "sysemu/sysemu.h"
#include "sysemu/kvm.h"
#include "cpu.h"
#include "sysemu/cpus.h"
#include "kvm_mips.h"

//#define DEBUG_KVM

#ifdef DEBUG_KVM
#define dprintf(fmt, ...) \
    do { fprintf(stderr, fmt, ## __VA_ARGS__); } while (0)
#else
#define dprintf(fmt, ...) \
    do { } while (0)
#endif

extern int64_t g_kernel_entry;

static int kvm_mips_vz_cap = 0;

const KVMCapabilityInfo kvm_arch_required_capabilities[] = {
    KVM_CAP_LAST_INFO
};

unsigned long kvm_arch_vcpu_id(CPUState *cpu)
{
    return cpu->cpu_index;
}

int kvm_arch_init(KVMState *s)
{
    dprintf("%s\n", __func__);
    kvm_mips_vz_cap = kvm_check_extension(s, KVM_CAP_MIPS_VZ_ASE);
    return 0;
}

int kvm_arch_init_vcpu(CPUState *env)
{
    dprintf("%s\n", __func__);
    return 0;
}

void kvm_arch_reset_vcpu(CPUState *env)
{
    dprintf("%s\n", __func__);
#if 0
    int ret;

    ret = kvm_vcpu_ioctl(env, KVM_NMI);
    if (ret < 0) {
        fprintf(stderr, "KVM: injection failed, NMI lost (%s)\n",
        strerror(-ret));
    }
#endif
}

int kvm_arch_put_registers(CPUState *cs, int level)
{
    MIPSCPU *cpu = MIPS_CPU(cs);
    CPUMIPSState *env = &cpu->env;
    struct kvm_regs regs;
    int ret;
    int i;

    /* Set the registers based on QEMU's view of things */
    for (i = 0; i < 32; i++)
        regs.gpr[i] = env->active_tc.gpr[i];

    regs.hi = env->active_tc.HI[0];
    regs.lo = env->active_tc.LO[0];
    regs.pc = env->active_tc.PC;

    ret = kvm_vcpu_ioctl(cs, KVM_SET_REGS, &regs);

    if (ret < 0) {
        return ret;
    }

#ifdef CONFIG_KVM_MIPS_VZ
    ret = kvm_mips_vz_put_cp0_registers(cs, KVM_PUT_FULL_STATE);
#else
    ret = kvm_mips_te_put_cp0_registers(cs, KVM_PUT_FULL_STATE);
#endif

    return ret;
}

int kvm_arch_get_registers(CPUState *cs)
{
    MIPSCPU *cpu = MIPS_CPU(cs);
    CPUMIPSState *env = &cpu->env;
    int ret = 0;
    struct kvm_regs regs;
    int i;

    /* Get the current register set as KVM seems it */
    ret = kvm_vcpu_ioctl(cs, KVM_GET_REGS, &regs);

    if (ret < 0)
        return ret;

    for (i = 0;i < 32; i++)
        env->active_tc.gpr[i] = regs.gpr[i];

    env->active_tc.HI[0] = regs.hi;
    env->active_tc.LO[0] = regs.lo;
    env->active_tc.PC = regs.pc;

#ifdef CONFIG_KVM_MIPS_VZ
    kvm_mips_vz_get_cp0_registers(cs);
#else
    kvm_mips_te_get_cp0_registers(cs);
#endif

    return ret;
}

int kvm_arch_insert_sw_breakpoint(CPUState *env, struct kvm_sw_breakpoint *bp)
{
    dprintf("%s\n", __func__);
    return 0;
}

int kvm_arch_remove_sw_breakpoint(CPUState *env, struct kvm_sw_breakpoint *bp)
{
    dprintf("%s\n", __func__);
    return 0;
}

static inline int cpu_mips_io_interrupts_pending(CPUArchState *env)
{
    dprintf("%s: %#x\n", __func__, env->CP0_Cause & (1 << (2 + CP0Ca_IP)));
    return(env->CP0_Cause & (0x1 << (2 + CP0Ca_IP)));
}

void kvm_arch_pre_run(CPUState *cs, struct kvm_run *run)
{
    MIPSCPU *cpu = MIPS_CPU(cs);
    CPUMIPSState *env = &cpu->env;
    int r;
    struct kvm_mips_interrupt intr;

    if ((cs->interrupt_request & CPU_INTERRUPT_HARD) &&
        (cpu_mips_io_interrupts_pending(env)))
    {
        intr.cpu = -1;
        intr.irq = 2;
        r = kvm_vcpu_ioctl(cs, KVM_INTERRUPT, &intr);
        if (r < 0)
            printf("cpu %d fail inject %x\n", cs->cpu_index, intr.irq);
    }
    /* If we have an interrupt but the guest is not ready to receive an
     * interrupt, request an interrupt window exit.  This will
     * cause a return to userspace as soon as the guest is ready to
     * receive interrupts.
     */
    if ((cs->interrupt_request & CPU_INTERRUPT_HARD)) {
        run->request_interrupt_window = 1;
    } else {
        run->request_interrupt_window = 0;
    }
}

void kvm_arch_post_run(CPUState *env, struct kvm_run *run)
{
    dprintf("%s\n", __func__);
}

int kvm_arch_process_async_events(CPUState *cs)
{
    dprintf("%s\n", __func__);
    return cs->halted;
}

int kvm_arch_handle_exit(CPUState *env, struct kvm_run *run)
{
    int ret;

    printf("kvm_arch_handle_exit()\n");
    switch (run->exit_reason) {
    default:
        fprintf(stderr, "KVM: unknown exit reason %d\n", run->exit_reason);
        ret = -1;
        break;
    }

    return ret;
}

bool kvm_arch_stop_on_emulation_error(CPUState *env)
{
    dprintf("%s\n", __func__);
    return true;
}

int kvm_arch_on_sigbus_vcpu(CPUState *env, int code, void *addr)
{
    dprintf("%s\n", __func__);
    return 1;
}

int kvm_arch_on_sigbus(int code, void *addr)
{
    dprintf("%s\n", __func__);
    return 1;
}

int kvm_mips_set_interrupt(CPUMIPSState *env, int irq, int level)
{
    CPUState *cs = ENV_GET_CPU(env);
    struct kvm_mips_interrupt intr;

    if (!kvm_enabled()) {
        return 0;
    }

    intr.cpu = -1;

    if (level)
        intr.irq = irq;
    else
        intr.irq = -irq;

    kvm_vcpu_ioctl(cs, KVM_INTERRUPT, &intr);

    return 0;
}

int kvm_mips_set_ipi_interrupt(CPUArchState *env, int irq, int level)
{
    CPUState *cs = ENV_GET_CPU(cpu_single_env);
    CPUState *dest_cs = ENV_GET_CPU(env);
    struct kvm_mips_interrupt intr;

    if (!kvm_enabled()) {
        return 0;
    }

    intr.cpu = dest_cs->cpu_index;

    if (level)
        intr.irq = irq;
    else
        intr.irq = -irq;

    dprintf("%s: CPU %d, IRQ: %d\n", __func__, intr.cpu, intr.irq);

    kvm_vcpu_ioctl(cs, KVM_INTERRUPT, &intr);

    return 0;
}

int kvm_mips_vz_capability(CPUArchState *env)
{
    if (!kvm_enabled()) {
        return false;
    }

    return kvm_mips_vz_cap;
}

#define KVM_REG_MIPS_CP0_INDEX (0x10000 + 8 * 0 + 0)
#define KVM_REG_MIPS_CP0_ENTRYLO0 (0x10000 + 8 * 2 + 0)
#define KVM_REG_MIPS_CP0_ENTRYLO1 (0x10000 + 8 * 3 + 0)
#define KVM_REG_MIPS_CP0_CONTEXT (0x10000 + 8 * 4 + 0)
#define KVM_REG_MIPS_CP0_USERLOCAL (0x10000 + 8 * 4 + 2)
#define KVM_REG_MIPS_CP0_PAGEMASK (0x10000 + 8 * 5 + 0)
#define KVM_REG_MIPS_CP0_PAGEGRAIN (0x10000 + 8 * 5 + 1)
#define KVM_REG_MIPS_CP0_WIRED (0x10000 + 8 * 6 + 0)
#define KVM_REG_MIPS_CP0_HWRENA (0x10000 + 8 * 7 + 0)
#define KVM_REG_MIPS_CP0_BADVADDR (0x10000 + 8 * 8 + 0)
#define KVM_REG_MIPS_CP0_COUNT (0x10000 + 8 * 9 + 0)
#define KVM_REG_MIPS_CP0_ENTRYHI (0x10000 + 8 * 10 + 0)
#define KVM_REG_MIPS_CP0_COMPARE (0x10000 + 8 * 11 + 0)
#define KVM_REG_MIPS_CP0_STATUS (0x10000 + 8 * 12 + 0)
#define KVM_REG_MIPS_CP0_INTCTL (0x10000 + 8 * 12 + 1)
#define KVM_REG_MIPS_CP0_CAUSE (0x10000 + 8 * 13 + 0)
#define KVM_REG_MIPS_CP0_EPC (0x10000 + 8 * 14 + 0)
#define KVM_REG_MIPS_CP0_PRID (0x10000 + 8 * 15 + 0)
#define KVM_REG_MIPS_CP0_EBASE (0x10000 + 8 * 15 + 1)
#define KVM_REG_MIPS_CP0_CONFIG (0x10000 + 8 * 16 + 0)
#define KVM_REG_MIPS_CP0_CONFIG1 (0x10000 + 8 * 16 + 1)
#define KVM_REG_MIPS_CP0_CONFIG2 (0x10000 + 8 * 16 + 2)
#define KVM_REG_MIPS_CP0_CONFIG3 (0x10000 + 8 * 16 + 3)
#define KVM_REG_MIPS_CP0_CONFIG4 (0x10000 + 8 * 16 + 4)
#define KVM_REG_MIPS_CP0_CONFIG5 (0x10000 + 8 * 16 + 5)
#define KVM_REG_MIPS_CP0_CONFIG7 (0x10000 + 8 * 16 + 7)
#define KVM_REG_MIPS_CP0_XCONTEXT (0x10000 + 8 * 20 + 0)
#define KVM_REG_MIPS_CP0_ERROREPC (0x10000 + 8 * 30 + 0)

inline int kvm_mips_put_one_reg(CPUState *cs, int reg_id, int32 *addr)
{
    __u64 val64 = (__u64)*addr;
    struct kvm_one_reg cp0reg = { .id = reg_id, .addr = (__u64)((target_ulong)&val64) };

    return kvm_vcpu_ioctl(cs, KVM_SET_ONE_REG, &cp0reg);
}

inline int kvm_mips_put_one_ulreg(CPUState *cs, int reg_id, target_ulong *addr)
{
    __u64 val64 = (__u64)*addr;
    struct kvm_one_reg cp0reg = { .id = reg_id, .addr = (__u64)((target_ulong)&val64) };

    return kvm_vcpu_ioctl(cs, KVM_SET_ONE_REG, &cp0reg);
}

inline int kvm_mips_get_one_reg(CPUState *cs, int reg_id, int32 *addr)
{
    int ret;
    __u64 val64 = 0;
    struct kvm_one_reg cp0reg = { .id = reg_id, .addr = (__u64)((target_ulong)&val64) };

    ret = kvm_vcpu_ioctl(cs, KVM_GET_ONE_REG, &cp0reg);
    if (ret < 0)
        return ret;

    *addr = (int32)val64;
    return ret;
}

inline int kvm_mips_get_one_ulreg(CPUState *cs, int reg_id, target_ulong *addr)
{
    int ret;
    __u64 val64 = 0;
    struct kvm_one_reg cp0reg = { .id = reg_id, .addr = (__u64)((target_ulong)&val64) };

    ret = kvm_vcpu_ioctl(cs, KVM_GET_ONE_REG, &cp0reg);
    if (ret < 0)
        return ret;

    *addr = (target_ulong)val64;
    return ret;
}

int kvm_mips_vz_put_cp0_registers(CPUState *cs, int level)
{
    MIPSCPU *cpu = MIPS_CPU(cs);
    CPUMIPSState *env = &cpu->env;
    int ret;

    // TODO consider using KVM_PUT_FULL_STATE, KVM_PUT_RUNTIME_STATE etc...
    (void)level;

    ret = kvm_mips_put_one_reg(cs, KVM_REG_MIPS_CP0_INDEX, &env->CP0_Index);
    if (ret < 0) return ret;
    ret |= kvm_mips_put_one_ulreg(cs, KVM_REG_MIPS_CP0_ENTRYLO0, &env->CP0_EntryLo0);
    if (ret < 0) return ret;
    ret |= kvm_mips_put_one_ulreg(cs, KVM_REG_MIPS_CP0_ENTRYLO1, &env->CP0_EntryLo1);
    if (ret < 0) return ret;
    ret |= kvm_mips_put_one_ulreg(cs, KVM_REG_MIPS_CP0_CONTEXT, &env->CP0_Context);
    if (ret < 0) return ret;
    ret |= kvm_mips_put_one_reg(cs, KVM_REG_MIPS_CP0_PAGEMASK, &env->CP0_PageMask);
    if (ret < 0) return ret;
    ret |= kvm_mips_put_one_reg(cs, KVM_REG_MIPS_CP0_PAGEGRAIN, &env->CP0_PageGrain);
    if (ret < 0) return ret;
    ret |= kvm_mips_put_one_reg(cs, KVM_REG_MIPS_CP0_WIRED, &env->CP0_Wired);
    if (ret < 0) return ret;
    ret |= kvm_mips_put_one_reg(cs, KVM_REG_MIPS_CP0_HWRENA, &env->CP0_HWREna);
    if (ret < 0) return ret;
    ret |= kvm_mips_put_one_ulreg(cs, KVM_REG_MIPS_CP0_BADVADDR, &env->CP0_BadVAddr);
    if (ret < 0) return ret;
    ret |= kvm_mips_put_one_reg(cs, KVM_REG_MIPS_CP0_COUNT, &env->CP0_Count);
    if (ret < 0) return ret;
    ret |= kvm_mips_put_one_ulreg(cs, KVM_REG_MIPS_CP0_ENTRYHI, &env->CP0_EntryHi);
    if (ret < 0) return ret;
    ret |= kvm_mips_put_one_reg(cs, KVM_REG_MIPS_CP0_COMPARE, &env->CP0_Compare);
    if (ret < 0) return ret;
    ret |= kvm_mips_put_one_reg(cs, KVM_REG_MIPS_CP0_STATUS, &env->CP0_Status);
    if (ret < 0) return ret;
    ret |= kvm_mips_put_one_reg(cs, KVM_REG_MIPS_CP0_INTCTL, &env->CP0_IntCtl);
    if (ret < 0) return ret;
    ret |= kvm_mips_put_one_reg(cs, KVM_REG_MIPS_CP0_CAUSE, &env->CP0_Cause);
    if (ret < 0) return ret;
    ret |= kvm_mips_put_one_ulreg(cs, KVM_REG_MIPS_CP0_EPC, &env->CP0_EPC);
    if (ret < 0) return ret;
    ret |= kvm_mips_put_one_reg(cs, KVM_REG_MIPS_CP0_PRID, &env->CP0_PRid);
    if (ret < 0) return ret;
    ret |= kvm_mips_put_one_reg(cs, KVM_REG_MIPS_CP0_EBASE, &env->CP0_EBase);
    if (ret < 0) return ret;
    ret |= kvm_mips_put_one_ulreg(cs, KVM_REG_MIPS_CP0_ERROREPC, &env->CP0_ErrorEPC);
    if (ret < 0) return ret;

    ret |= kvm_mips_put_one_reg(cs, KVM_REG_MIPS_CP0_CONFIG, &env->CP0_Config0);
    if (ret < 0) return ret;

    if (env->CP0_Config0 & 0x80000000) {
        ret |= kvm_mips_put_one_reg(cs, KVM_REG_MIPS_CP0_CONFIG1, &env->CP0_Config1);
        if (ret < 0) return ret;
    }

    if (env->CP0_Config1 & 0x80000000) {
        ret |= kvm_mips_put_one_reg(cs, KVM_REG_MIPS_CP0_CONFIG2, &env->CP0_Config2);
        if (ret < 0) return ret;
    }

    if (env->CP0_Config2 & 0x80000000) {
        ret |= kvm_mips_put_one_reg(cs, KVM_REG_MIPS_CP0_CONFIG3, &env->CP0_Config3);
        if (ret < 0) return ret;
    }

    if (env->CP0_Config3 & 0x80000000) {
        ret |= kvm_mips_put_one_reg(cs, KVM_REG_MIPS_CP0_CONFIG4, &env->CP0_Config4);
        if (ret < 0) return ret;
    }

    if (env->CP0_Config4 & 0x80000000) {
        ret |= kvm_mips_put_one_reg(cs, KVM_REG_MIPS_CP0_CONFIG5, &env->CP0_Config5);
        if (ret < 0) return ret;
    }
     
#if 0
    ret |= kvm_mips_put_one_reg(cs, KVM_REG_MIPS_CP0_CONFIG6, &env->CP0_Config6);
    if (ret < 0) return ret;
#endif

    ret |= kvm_mips_put_one_reg(cs, KVM_REG_MIPS_CP0_CONFIG7, &env->CP0_Config7);
    if (ret < 0) return ret;

    return ret;
}

int kvm_mips_vz_get_cp0_registers(CPUState *cs)
{
    MIPSCPU *cpu = MIPS_CPU(cs);
    CPUMIPSState *env = &cpu->env;
    int ret;

    ret = kvm_mips_get_one_reg(cs, KVM_REG_MIPS_CP0_INDEX, &env->CP0_Index);
    if (ret < 0) return ret;
    ret |= kvm_mips_get_one_ulreg(cs, KVM_REG_MIPS_CP0_ENTRYLO0, &env->CP0_EntryLo0);
    if (ret < 0) return ret;
    ret |= kvm_mips_get_one_ulreg(cs, KVM_REG_MIPS_CP0_ENTRYLO1, &env->CP0_EntryLo1);
    if (ret < 0) return ret;
    ret |= kvm_mips_get_one_ulreg(cs, KVM_REG_MIPS_CP0_CONTEXT, &env->CP0_Context);
    if (ret < 0) return ret;
    ret |= kvm_mips_get_one_reg(cs, KVM_REG_MIPS_CP0_PAGEMASK, &env->CP0_PageMask);
    if (ret < 0) return ret;
    ret |= kvm_mips_get_one_reg(cs, KVM_REG_MIPS_CP0_PAGEGRAIN, &env->CP0_PageGrain);
    if (ret < 0) return ret;
    ret |= kvm_mips_get_one_reg(cs, KVM_REG_MIPS_CP0_WIRED, &env->CP0_Wired);
    if (ret < 0) return ret;
    ret |= kvm_mips_get_one_reg(cs, KVM_REG_MIPS_CP0_HWRENA, &env->CP0_HWREna);
    if (ret < 0) return ret;
    ret |= kvm_mips_get_one_ulreg(cs, KVM_REG_MIPS_CP0_BADVADDR, &env->CP0_BadVAddr);
    if (ret < 0) return ret;
    ret |= kvm_mips_get_one_reg(cs, KVM_REG_MIPS_CP0_COUNT, &env->CP0_Count);
    if (ret < 0) return ret;
    ret |= kvm_mips_get_one_ulreg(cs, KVM_REG_MIPS_CP0_ENTRYHI, &env->CP0_EntryHi);
    if (ret < 0) return ret;
    ret |= kvm_mips_get_one_reg(cs, KVM_REG_MIPS_CP0_COMPARE, &env->CP0_Compare);
    if (ret < 0) return ret;
    ret |= kvm_mips_get_one_reg(cs, KVM_REG_MIPS_CP0_STATUS, &env->CP0_Status);
    if (ret < 0) return ret;
    ret |= kvm_mips_get_one_reg(cs, KVM_REG_MIPS_CP0_INTCTL, &env->CP0_IntCtl);
    if (ret < 0) return ret;
    ret |= kvm_mips_get_one_reg(cs, KVM_REG_MIPS_CP0_CAUSE, &env->CP0_Cause);
    if (ret < 0) return ret;
    ret |= kvm_mips_get_one_ulreg(cs, KVM_REG_MIPS_CP0_EPC, &env->CP0_EPC);
    if (ret < 0) return ret;
    ret |= kvm_mips_get_one_reg(cs, KVM_REG_MIPS_CP0_PRID, &env->CP0_PRid);
    if (ret < 0) return ret;
    ret |= kvm_mips_get_one_reg(cs, KVM_REG_MIPS_CP0_EBASE, &env->CP0_EBase);
    if (ret < 0) return ret;
    ret |= kvm_mips_get_one_ulreg(cs, KVM_REG_MIPS_CP0_ERROREPC, &env->CP0_ErrorEPC);
    if (ret < 0) return ret;

    // only get implemented config registers
    env->CP0_Config1 = 0;
    env->CP0_Config2 = 0;
    env->CP0_Config3 = 0;
    env->CP0_Config4 = 0;
    env->CP0_Config5 = 0;
    env->CP0_Config6 = 0;

    ret |= kvm_mips_get_one_reg(cs, KVM_REG_MIPS_CP0_CONFIG, &env->CP0_Config0);
    if (ret < 0) return ret;

    if (env->CP0_Config0 & 0x80000000) {
        ret |= kvm_mips_get_one_reg(cs, KVM_REG_MIPS_CP0_CONFIG1, &env->CP0_Config1);
        if (ret < 0) return ret;
    }

    if (env->CP0_Config1 & 0x80000000) {
        ret |= kvm_mips_get_one_reg(cs, KVM_REG_MIPS_CP0_CONFIG2, &env->CP0_Config2);
        if (ret < 0) return ret;
    }

    if (env->CP0_Config2 & 0x80000000) {
        ret |= kvm_mips_get_one_reg(cs, KVM_REG_MIPS_CP0_CONFIG3, &env->CP0_Config3);
        if (ret < 0) return ret;
    }

    if (env->CP0_Config3 & 0x80000000) {
        ret |= kvm_mips_get_one_reg(cs, KVM_REG_MIPS_CP0_CONFIG4, &env->CP0_Config4);
        if (ret < 0) return ret;
    }

    if (env->CP0_Config4 & 0x80000000) {
        ret |= kvm_mips_get_one_reg(cs, KVM_REG_MIPS_CP0_CONFIG5, &env->CP0_Config5);
        if (ret < 0) return ret;
    }
     
#if 0
    ret |= kvm_mips_get_one_reg(cs, KVM_REG_MIPS_CP0_CONFIG6, &env->CP0_Config6);
    if (ret < 0) return ret;
#endif

    ret |= kvm_mips_get_one_reg(cs, KVM_REG_MIPS_CP0_CONFIG7, &env->CP0_Config7);

    return ret;
}

int kvm_mips_te_put_cp0_registers(CPUState *cs, int level)
{
    MIPSCPU *cpu = MIPS_CPU(cs);
    CPUMIPSState *env = &cpu->env;
    int ret;

    // TODO consider using KVM_PUT_FULL_STATE, KVM_PUT_RUNTIME_STATE etc...
    (void)level;

    ret = kvm_mips_put_one_reg(cs, KVM_REG_MIPS_CP0_INDEX, &env->CP0_Index);
    if (ret < 0) return ret;
    ret |= kvm_mips_put_one_ulreg(cs, KVM_REG_MIPS_CP0_CONTEXT, &env->CP0_Context);
    if (ret < 0) return ret;
    ret |= kvm_mips_put_one_reg(cs, KVM_REG_MIPS_CP0_PAGEMASK, &env->CP0_PageMask);
    if (ret < 0) return ret;
    ret |= kvm_mips_put_one_reg(cs, KVM_REG_MIPS_CP0_WIRED, &env->CP0_Wired);
    if (ret < 0) return ret;
    ret |= kvm_mips_put_one_ulreg(cs, KVM_REG_MIPS_CP0_BADVADDR, &env->CP0_BadVAddr);
    if (ret < 0) return ret;
    ret |= kvm_mips_put_one_reg(cs, KVM_REG_MIPS_CP0_COUNT, &env->CP0_Count);
    if (ret < 0) return ret;
    ret |= kvm_mips_put_one_ulreg(cs, KVM_REG_MIPS_CP0_ENTRYHI, &env->CP0_EntryHi);
    if (ret < 0) return ret;
    ret |= kvm_mips_put_one_reg(cs, KVM_REG_MIPS_CP0_COMPARE, &env->CP0_Compare);
    if (ret < 0) return ret;
    ret |= kvm_mips_put_one_reg(cs, KVM_REG_MIPS_CP0_STATUS, &env->CP0_Status);
    if (ret < 0) return ret;
    ret |= kvm_mips_put_one_reg(cs, KVM_REG_MIPS_CP0_CAUSE, &env->CP0_Cause);
    if (ret < 0) return ret;
    ret |= kvm_mips_put_one_ulreg(cs, KVM_REG_MIPS_CP0_EPC, &env->CP0_EPC);
    if (ret < 0) return ret;
    ret |= kvm_mips_put_one_ulreg(cs, KVM_REG_MIPS_CP0_ERROREPC, &env->CP0_ErrorEPC);
    if (ret < 0) return ret;

    return ret;
}

int kvm_mips_te_get_cp0_registers(CPUState *cs)
{
    MIPSCPU *cpu = MIPS_CPU(cs);
    CPUMIPSState *env = &cpu->env;
    int ret;

    ret = kvm_mips_get_one_reg(cs, KVM_REG_MIPS_CP0_INDEX, &env->CP0_Index);
    if (ret < 0) return ret;
    ret |= kvm_mips_get_one_ulreg(cs, KVM_REG_MIPS_CP0_CONTEXT, &env->CP0_Context);
    if (ret < 0) return ret;
    ret |= kvm_mips_get_one_reg(cs, KVM_REG_MIPS_CP0_PAGEMASK, &env->CP0_PageMask);
    if (ret < 0) return ret;
    ret |= kvm_mips_get_one_reg(cs, KVM_REG_MIPS_CP0_WIRED, &env->CP0_Wired);
    if (ret < 0) return ret;
    ret |= kvm_mips_get_one_ulreg(cs, KVM_REG_MIPS_CP0_BADVADDR, &env->CP0_BadVAddr);
    if (ret < 0) return ret;
    ret |= kvm_mips_get_one_reg(cs, KVM_REG_MIPS_CP0_COUNT, &env->CP0_Count);
    if (ret < 0) return ret;
    ret |= kvm_mips_get_one_ulreg(cs, KVM_REG_MIPS_CP0_ENTRYHI, &env->CP0_EntryHi);
    if (ret < 0) return ret;
    ret |= kvm_mips_get_one_reg(cs, KVM_REG_MIPS_CP0_COMPARE, &env->CP0_Compare);
    if (ret < 0) return ret;
    ret |= kvm_mips_get_one_reg(cs, KVM_REG_MIPS_CP0_STATUS, &env->CP0_Status);
    if (ret < 0) return ret;
    ret |= kvm_mips_get_one_reg(cs, KVM_REG_MIPS_CP0_CAUSE, &env->CP0_Cause);
    if (ret < 0) return ret;
    ret |= kvm_mips_get_one_ulreg(cs, KVM_REG_MIPS_CP0_EPC, &env->CP0_EPC);
    if (ret < 0) return ret;
    ret |= kvm_mips_get_one_ulreg(cs, KVM_REG_MIPS_CP0_ERROREPC, &env->CP0_ErrorEPC);
    if (ret < 0) return ret;

    return ret;
}
