#ifndef HW_MIPS_CPUDEVS_H
#define HW_MIPS_CPUDEVS_H
/* Definitions for MIPS CPU internal devices.  */

/* mips_addr.c */
uint64_t cpu_mips_kseg0_to_phys(void *opaque, uint64_t addr);
uint64_t cpu_mips_phys_to_kseg0(void *opaque, uint64_t addr);

uint64_t cpu_mips_kvm_um_kseg0_to_phys(void *opaque, uint64_t addr);
uint64_t cpu_mips_kvm_um_phys_to_kseg0(void *opaque, uint64_t addr);

/* KVM runs in UM when the VZ ASE is not supported */
uint64_t cpu_mips_kvm_vz_kseg0_to_phys(void *opaque, uint64_t addr);
uint64_t cpu_mips_kvm_vz_phys_to_kseg0(void *opaque, uint64_t addr);

/* mips_int.c */
void cpu_mips_irq_init_cpu(CPUMIPSState *env);

/* mips_timer.c */
void cpu_mips_clock_init(CPUMIPSState *);

#endif
