/* ===== EXCERPT — Ghidra decompiler output derived from Google's copyrighted
 * kernel binary. Trimmed to the two functions F38/F22 cite (yaffs_retype_obj,
 * yaffs_oh_to_size); yaffs_new_obj and the rest are NOT checked in. Regenerate
 * from your own OTA per evidence/README-yaffs-decompiles.md. Typing is heuristic. */

/* ===== yaffs_retype_obj @ c028d180 ===== */
/* The function the scan path calls on a type mismatch (see yaffs-decomp.c @ c02942c4):
 * it tears down the old variant union (switch on obj->variant_type @ +100) and
 * re-initializes the object as param_2's type. Its presence is the 2014 upstream fix. */

int yaffs_retype_obj(int param_1,int param_2,undefined4 param_3,undefined4 param_4)

{
  int *piVar1;
  int extraout_r3;
  int iVar2;
  int *piVar3;
  int iVar4;
  int *piVar5;
  undefined4 uVar6;

  switch(*(undefined4 *)(param_1 + 100)) {
  case 1:
    yaffs_resize_file(param_1,param_2,0,0,param_4);
    iVar2 = *(int *)(param_1 + 8);
    yaffs_free_raw_tnode(iVar2,*(undefined4 *)(param_1 + 0x84));
    *(undefined4 *)(iVar2 + 0x120) = 0;
    *(int *)(iVar2 + 0x14c) = *(int *)(iVar2 + 0x14c) + -1;
    *(undefined4 *)(param_1 + 0x84) = 0;
    break;
  case 2:
    kfree(*(undefined4 *)(param_1 + 0x68));
    *(undefined4 *)(param_1 + 0x68) = 0;
    break;
  case 3:
    piVar5 = (int *)(param_1 + 0x68);
    piVar1 = (int *)*piVar5;
    uVar6 = *(undefined4 *)(*(int *)(param_1 + 8) + 0xd90);
    piVar3 = (int *)*piVar1;
    if (piVar1 == piVar5) {
      iVar2 = *(int *)(param_1 + 0x70);
      if (iVar2 == param_1 + 0x70) break;
    }
    else {
      while( true ) {
        yaffs_add_obj_to_dir(uVar6,piVar1 + -8);
        if (piVar5 == piVar3) break;
        piVar1 = piVar3;
        piVar3 = (int *)*piVar3;
      }
      iVar2 = *(int *)(param_1 + 0x70);
      if (iVar2 == param_1 + 0x70) break;
    }
    piVar1 = *(int **)(param_1 + 0x74);
    *(int **)(iVar2 + 4) = piVar1;
    *piVar1 = iVar2;
    iVar2 = param_1 + 0x70;
    *(int *)iVar2 = iVar2;
    *(int *)(param_1 + 0x74) = iVar2;
    break;
  case 4:
    piVar1 = *(int **)(param_1 + 0x18);
    iVar2 = *(int *)(param_1 + 0x14);
    *(int **)(iVar2 + 4) = piVar1;
    *piVar1 = iVar2;
    *(int *)(param_1 + 0x14) = param_1 + 0x14;
    *(int *)(param_1 + 0x18) = param_1 + 0x14;
  }
  iVar4 = param_1 + 0x68;
  __memzero(iVar4,0x20);
  iVar2 = extraout_r3;
  if (param_2 == 3) {
    iVar2 = param_1 + 0x70;
    *(int *)(param_1 + 0x68) = iVar4;
    *(int *)(param_1 + 0x6c) = iVar4;
  }
  *(int *)(param_1 + 100) = param_2;
  if (param_2 == 3) {
    *(int *)(param_1 + 0x70) = iVar2;
    *(int *)(param_1 + 0x74) = iVar2;
  }
  return param_1;
}



/* ===== yaffs_oh_to_size @ c028ea04 ===== */

undefined8 yaffs_oh_to_size(int param_1)

{
  int iVar1;
  undefined4 uVar2;

  iVar1 = *(int *)(param_1 + 0x1f0);
  if (iVar1 == -1) {
    uVar2 = *(undefined4 *)(param_1 + 0x124);
    iVar1 = 0;
  }
  else {
    uVar2 = *(undefined4 *)(param_1 + 0x124);
  }
  return CONCAT44(iVar1,uVar2);
}
