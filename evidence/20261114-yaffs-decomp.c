/* ===== yaffs2_scan_backwards @ c0293bcc — EXCERPT ===== */
/* Trimmed to the object-confusion / retype region F38 cites. This is Ghidra
 * decompiler output derived from Google's copyrighted kernel binary; the full
 * ~0x1030-byte function is NOT checked in. Regenerate from your own OTA per
 * evidence/README-yaffs-decompiles.md.  (Ghidra typing/offsets are heuristic.) */

/* [... object-header data-chunk path, local_8c = the object named by obj_id ...] */

                local_8c = (byte *)yaffs_find_or_create_by_number(param_1,local_74,local_44);
                /* [...] */
LAB_c0294280:
                if (local_a8 == (int *)0x0) {
                  iVar7 = local_44;
                }
                else {
                  iVar7 = *local_a8;                       /* expected type from object header   */
                }
                /* --- the type-mismatch guard (2014 upstream fix shape; cf. F22/F38) --- */
                if (*(int *)(local_8c + 100) != iVar7) {   /* obj->variant_type (@+100) != expected */
                  if ((DAT_c06c9ea4 & 0x40000000) != 0) {
                    if (local_a8 == (int *)0x0) { iVar7 = local_44; } else { iVar7 = *local_a8; }
                    printk(&DAT_c0645638,iVar7,*(int *)(local_8c + 100),local_74,iVar15);
                  }
                  if (local_a8 == (int *)0x0) { iVar7 = local_44; } else { iVar7 = *local_a8; }
                  local_8c = (byte *)yaffs_retype_obj(local_8c,iVar7);  /* <-- retype on mismatch */
                  if ((*local_8c & 0x80) != 0) goto LAB_c029443c;
                }
                if (1 < local_74 - 1) {
                  *(int *)(local_8c + 0x28) = iVar15;
                  *local_8c = *local_8c | 0x80;
                  if (local_a8 == (int *)0x0) {
                    *(int *)(local_8c + 100) = local_44;
                    iVar15 = yaffs_find_or_create_by_number(param_1,local_50,3);  /* r2=#3 TYPE_FILE */
                    /* [...] */
                  }
                  else {
                    *(int *)(local_8c + 100) = *local_a8;
                    /* [...] */
                    iVar15 = yaffs_find_or_create_by_number(param_1,local_a8[1],3);
                    uVar20 = yaffs_oh_to_size(local_a8);    /* consumes returned obj as a FILE    */
                    /* [...] */
                  }
                  /* [...] */
                  if (iVar15 == 0) {
                    local_b0 = (int *)0x1;
LAB_c0294714:
                    /* [...] */
                    iVar15 = *(int *)(param_1 + 0xd90);
                  }
                  else if (*(int *)(iVar15 + 100) == 0) {   /* parent was untyped -> make it a dir */
                    *(undefined4 *)(iVar15 + 100) = 3;
                    *(int *)(iVar15 + 0x68) = iVar15 + 0x68;
                    *(int *)(iVar15 + 0x6c) = iVar15 + 0x68;
                  }
                  else if (*(int *)(iVar15 + 100) != 3) goto LAB_c0294714;  /* parent type-checked */
                  yaffs_add_obj_to_dir(iVar15,local_8c);
                  /* [...] */
                }

/* [... remainder of yaffs2_scan_backwards elided ...] */
