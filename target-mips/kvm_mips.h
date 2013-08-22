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

#ifndef __KVM_MIPS_H__
#define __KVM_MIPS_H__


int kvm_mips_set_interrupt(CPUMIPSState *env, int irq, int level);

int kvm_mips_set_ipi_interrupt(CPUArchState *env, int irq, int level);

int kvm_mips_vz_capability(CPUArchState *env);

inline int kvm_mips_put_one_reg(CPUState *cs, int reg_id, int32 *addr);
inline int kvm_mips_put_one_ulreg(CPUState *cs, int reg_id, target_ulong *addr);
inline int kvm_mips_get_one_reg(CPUState *cs, int reg_id, int32 *addr);
inline int kvm_mips_get_one_ulreg(CPUState *cs, int reg_id, target_ulong *addr);

int kvm_mips_vz_put_cp0_registers(CPUState *cs, int level);
int kvm_mips_vz_get_cp0_registers(CPUState *cs);
int kvm_mips_te_put_cp0_registers(CPUState *cs, int level);
int kvm_mips_te_get_cp0_registers(CPUState *cs);


#endif /* __KVM_MIPS_H__ */
