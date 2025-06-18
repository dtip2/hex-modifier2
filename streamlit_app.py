# streamlit_app_v4.2_win7_fix.py
import streamlit as st
import binascii
import time

# --- Configuration ---
CONTEXT_LENGTH = 8

# --- Helper Functions ---
def load_file_to_bytes_streamlit(uploaded_file_object):
    if uploaded_file_object is not None:
        try: return uploaded_file_object.read()
        except Exception as e: st.error(f"Failed to load {uploaded_file_object.name}: {str(e)}"); return None
    return None

def count_byte_differences(bytes1, bytes2):
    if bytes1 is None or bytes2 is None: return 0
    try:
        min_len = min(len(bytes1), len(bytes2))
        diff_count = sum(bytes1[i] != bytes2[i] for i in range(min_len))
        diff_count += abs(len(bytes1) - len(bytes2))
        return diff_count
    except Exception as e: st.error(f"Error counting differences: {str(e)}"); return -1

def find_differences_with_context(file1_bytes, file2_bytes, context_len=CONTEXT_LENGTH):
    if file1_bytes is None or file2_bytes is None: return []
    changes = []
    len1, len2 = len(file1_bytes), len(file2_bytes)
    idx1, idx2 = 0, 0
    while idx1 < len1 or idx2 < len2:
        while idx1 < len1 and idx2 < len2 and file1_bytes[idx1] == file2_bytes[idx2]: idx1 += 1; idx2 += 1
        is_diff = (idx1 < len1 and idx2 < len2 and file1_bytes[idx1] != file2_bytes[idx2])
        is_f1_remaining = (idx1 < len1 and idx2 == len2)
        is_f2_remaining = (idx1 == len1 and idx2 < len2)
        if is_diff or is_f1_remaining or is_f2_remaining:
            diff_start_idx1, diff_start_idx2 = idx1, idx2
            original_offset_f1 = diff_start_idx1
            original_offset_f2 = diff_start_idx2
            actual_context_start1 = max(0, diff_start_idx1 - context_len)
            context_before = file1_bytes[actual_context_start1:diff_start_idx1]
            diff_end_idx1, diff_end_idx2 = idx1, idx2
            if is_diff:
                while diff_end_idx1 < len1 and diff_end_idx2 < len2 and \
                      file1_bytes[diff_end_idx1] != file2_bytes[diff_end_idx2]:
                    diff_end_idx1 += 1; diff_end_idx2 += 1
            elif is_f1_remaining: diff_end_idx1 = len1
            elif is_f2_remaining: diff_end_idx2 = len2
            if diff_end_idx1 == len1 and diff_end_idx2 < len2 and is_diff: diff_end_idx2 = len2
            elif diff_end_idx2 == len2 and diff_end_idx1 < len1 and is_diff: diff_end_idx1 = len1
            old_data = file1_bytes[diff_start_idx1:diff_end_idx1]
            new_data = file2_bytes[diff_start_idx2:diff_end_idx2]
            context_after_start1 = diff_end_idx1
            context_after_end1 = min(len1, context_after_start1 + context_len)
            context_after = file1_bytes[context_after_start1:context_after_end1]
            idx1 = diff_end_idx1; idx2 = diff_end_idx2
            changes.append({"original_offset": original_offset_f1,
                            "old_data_bytes": old_data, "new_data_bytes": new_data,
                            "context_before": context_before, "context_after": context_after,
                            "original_f2_offset_for_new_data": original_offset_f2,
                            "original_new_data_len": len(new_data)})
        else: break
    return changes

# --- Streamlit GUI Updater ---
class StreamlitGuiUpdate:
    def __init__(self, progress_bar_placeholder, status_text_placeholder):
        self.progress_bar_placeholder = progress_bar_placeholder
        self.status_text_placeholder = status_text_placeholder

    def put(self, item_tuple):
        if item_tuple is None:
            if self.status_text_placeholder:
                self.status_text_placeholder.success("Orchestrator processing finished signal received.")
            if 'live_log_messages' not in st.session_state:
                st.session_state.live_log_messages = []
            st.session_state.live_log_messages.append("Orchestrator signals end of passes.")
            st.session_state.live_log_messages = st.session_state.live_log_messages[-15:]
            return

        message_type, value = item_tuple
        
        if message_type == 'status':
            if self.status_text_placeholder:
                self.status_text_placeholder.info(f"{value}")
            if 'live_log_messages' not in st.session_state:
                st.session_state.live_log_messages = []
            st.session_state.live_log_messages.append(str(value))
            st.session_state.live_log_messages = st.session_state.live_log_messages[-15:]

        elif message_type == 'progress':
            if self.progress_bar_placeholder:
                progress_value = int(value)
                if 0 <= progress_value <= 100: self.progress_bar_placeholder.progress(progress_value)
                elif progress_value > 100: self.progress_bar_placeholder.progress(100)

# --- Patch Application Engine (Pass 1) ---
def apply_patches_pure_python_search(
    target_file_bytes_input, changes_to_attempt, gui_queue,
    strictness_level, pass_description="Pass",
    progress_start_percent=0, progress_scan_end_percent=40,
    progress_resolve_end_percent=50, progress_apply_end_percent=60
):
    def post_update(message_type, value): gui_queue.put((message_type, value))
    def post_status_update(message):
        full_message = f"Status: ({pass_description} - Strictness {strictness_level}) {message}"
        post_update('status', full_message)
    if target_file_bytes_input is None:
        post_status_update("Error: Input target data is missing.")
        return None, 0, [{"original_offset": -1, "patch_index": -1, "patch_number": "N/A", "reason": "Error: Input target data is missing."}], set()
    if not changes_to_attempt:
        post_status_update("No changes to attempt in this pass.")
        post_update('progress', progress_apply_end_percent); return target_file_bytes_input, 0, [], set()
    post_status_update(f"Starting..."); post_update('progress', progress_start_percent)
    patch_details_list_this_pass = [{} for _ in changes_to_attempt]; pattern_to_local_patch_indices = {}; unique_patterns = set()
    total_patches_this_pass = len(changes_to_attempt)
    post_status_update(f"Building search patterns for {total_patches_this_pass} patches..."); build_start_time = time.time()
    for i, change_obj in enumerate(changes_to_attempt):
        original_idx = change_obj["original_patch_index"]; original_patch_num = change_obj["patch_num_original"]
        old_data = change_obj["old_data_bytes"]; new_data = change_obj["new_data_bytes"]
        context_before = change_obj["context_before"]; context_after = change_obj["context_after"]
        patch_details_list_this_pass[i] = {"local_patch_index_this_pass": i, "original_patch_index": original_idx,
            "patch_num_original": original_patch_num, "old_data": old_data, "new_data": new_data,
            "original_offset_in_file1": change_obj["original_offset"],
            "context_before_hex": context_before.hex(sep=' '), "context_after_hex": context_after.hex(sep=' '), "patterns": []}
        patterns_to_try = []; pri = 0
        p_ctx_both = context_before + old_data + context_after if context_before and old_data and context_after else None
        p_ctx_b = context_before + old_data if context_before and old_data else None
        p_ctx_a = old_data + context_after if old_data and context_after else None
        p_old = old_data if old_data else None
        p_ins_ctx_both = context_before + context_after if not old_data and new_data and context_before and context_after else None
        p_ins_ctx_b = context_before if not old_data and new_data and context_before else None
        if strictness_level <= 6:
             if p_ctx_both: patterns_to_try.append((p_ctx_both, pri, len(context_before), "CtxBefore+Old+CtxAfter")); pri+=1
             if p_ins_ctx_both: patterns_to_try.append((p_ins_ctx_both, pri+0.1, len(context_before), "CtxBefore+CtxAfter (Insert)")); pri+=1
             if p_ins_ctx_b: patterns_to_try.append((p_ins_ctx_b, pri+0.2, len(context_before), "CtxBefore (Insert)")); pri+=1
        if strictness_level <= 5:
             if p_ctx_b: patterns_to_try.append((p_ctx_b, pri, len(context_before), "CtxBefore+Old")); pri+=1
             if p_ctx_a: patterns_to_try.append((p_ctx_a, pri, 0, "Old+CtxAfter")); pri+=1
        if strictness_level <= 4:
             if p_old: patterns_to_try.append((p_old, pri, 0, "Old Data Only")); pri+=1
        for pattern_bytes_loop, priority, ctx_b_len, desc in patterns_to_try:
            if not pattern_bytes_loop: continue
            pattern_info = {"pattern": pattern_bytes_loop, "priority": priority, "ctx_b_len": ctx_b_len, "desc": desc}
            patch_details_list_this_pass[i]["patterns"].append(pattern_info); unique_patterns.add(pattern_bytes_loop)
            if pattern_bytes_loop not in pattern_to_local_patch_indices: pattern_to_local_patch_indices[pattern_bytes_loop] = []
            if i not in pattern_to_local_patch_indices[pattern_bytes_loop]: pattern_to_local_patch_indices[pattern_bytes_loop].append(i)
    patterns_list = list(unique_patterns); build_end_time = time.time()
    current_progress_after_build = progress_start_percent + (progress_scan_end_percent - progress_start_percent) * 0.05
    post_update('progress', int(current_progress_after_build))
    post_status_update(f"Pattern analysis complete ({len(patterns_list)} unique) in {build_end_time - build_start_time:.2f}s. Searching target...")
    if not patterns_list:
         post_status_update(f"No search patterns generated."); skipped_details_this_pass = []
         for dp_idx, dp_val in enumerate(patch_details_list_this_pass):
              skipped_details_this_pass.append({ 
                  "original_patch_index": dp_val["original_patch_index"], "patch_number": dp_val["patch_num_original"],
                  "original_offset": dp_val["original_offset_in_file1"], "reason": f"P{dp_val['patch_num_original']}: No search patterns applicable for this diff block.",
                  "old_data_snippet": dp_val["old_data"][:16].hex(sep=' '), "new_data_snippet": dp_val["new_data"][:16].hex(sep=' '),
                  "context_before": dp_val["context_before_hex"], "context_after": dp_val["context_after_hex"], 
                })
         post_update('progress', progress_apply_end_percent); return target_file_bytes_input, 0, skipped_details_this_pass, set()
    found_matches_local = {}; search_start_time = time.time(); target_len = len(target_file_bytes_input)
    scan_progress_range = progress_scan_end_percent - current_progress_after_build; scan_count = 0
    for i_scan in range(target_len):
        scan_count += 1
        if scan_count > 0 and scan_count % 250000 == 0:
            sp_done = (i_scan / target_len) if target_len > 0 else 1; cs_prog = current_progress_after_build + (scan_progress_range * sp_done)
            post_update('progress', int(cs_prog)); post_status_update(f"Scanning target at offset {i_scan}/{target_len}...")
        for pattern_bytes_loop_2 in patterns_list:
             pattern_len = len(pattern_bytes_loop_2)
             if i_scan + pattern_len <= target_len and target_file_bytes_input[i_scan : i_scan + pattern_len] == pattern_bytes_loop_2:
                 matched_local_indices = pattern_to_local_patch_indices.get(pattern_bytes_loop_2, [])
                 for local_idx in matched_local_indices:
                     p_info = next((p for p in patch_details_list_this_pass[local_idx]["patterns"] if p["pattern"] == pattern_bytes_loop_2), None)
                     if p_info:
                         m_info = {"start_index_in_target": i_scan, **p_info}
                         if local_idx not in found_matches_local: found_matches_local[local_idx] = []
                         found_matches_local[local_idx].append(m_info)
    search_end_time = time.time(); post_update('progress', progress_scan_end_percent)
    post_status_update(f"Scan complete ({scan_count if scan_count > 0 else '0'}) in {search_end_time - search_start_time:.2f}s. Resolving matches...")
    patches_to_apply_this_pass = []; skipped_local_indices_map = {}; applied_local_indices_this_pass = set()
    resolve_start_time = time.time(); resolve_progress_range = progress_resolve_end_percent - progress_scan_end_percent
    for local_idx in range(total_patches_this_pass):
        if local_idx > 0 and local_idx % 250 == 0:
            rp_done = (local_idx / total_patches_this_pass) if total_patches_this_pass > 0 else 1
            cr_prog = progress_scan_end_percent + (resolve_progress_range * rp_done)
            post_update('progress', int(cr_prog)); post_status_update(f"Resolving patch {local_idx+1}/{total_patches_this_pass}...")
        patch_detail_pass = patch_details_list_this_pass[local_idx]; p_num_msg = patch_detail_pass["patch_num_original"]
        pot_matches = found_matches_local.get(local_idx, [])
        cs_info = {"original_patch_index": patch_detail_pass["original_patch_index"], "patch_number": p_num_msg,
            "original_offset": patch_detail_pass["original_offset_in_file1"], "old_data_snippet": patch_detail_pass["old_data"][:16].hex(sep=' '),
            "new_data_snippet": patch_detail_pass["new_data"][:16].hex(sep=' '), "context_before": patch_detail_pass["context_before_hex"],
            "context_after": patch_detail_pass["context_after_hex"],}
        if not pot_matches:
             if local_idx not in skipped_local_indices_map: skipped_local_indices_map[local_idx] = {**cs_info, "reason": f"P{p_num_msg}: No search patterns found in target file for this diff block."}
             continue
        pot_matches.sort(key=lambda m: (m["priority"], m["start_index_in_target"])); best_pri = pot_matches[0]["priority"]
        best_pri_matches = [m for m in pot_matches if m["priority"] == best_pri]; tdo_this_patch = {}
        for m in best_pri_matches:
             td_offset = m["start_index_in_target"] + m["ctx_b_len"]
             if td_offset not in tdo_this_patch: tdo_this_patch[td_offset] = []
             tdo_this_patch[td_offset].append(m)
        chosen_match = None; num_distinct_td_offsets = len(tdo_this_patch)
        if num_distinct_td_offsets == 1: chosen_match = list(tdo_this_patch.values())[0][0]
        elif num_distinct_td_offsets > 1:
            if strictness_level <= 2:
                 first_td_offset = min(tdo_this_patch.keys()); chosen_match = tdo_this_patch[first_td_offset][0]
                 post_status_update(f"P{p_num_msg}: Ambiguous ({num_distinct_td_offsets} targets for pattern '{chosen_match['desc']}') - Applying at 0x{first_td_offset:08X} (S{strictness_level})")
            else:
                 m_desc_amb = best_pri_matches[0]["desc"]; fto_hex = [f"0x{off:08X}" for off in sorted(tdo_this_patch.keys())[:5]]
                 reason_amb = (f"P{p_num_msg}: Ambiguous (S{strictness_level}+) - Pattern ('{m_desc_amb}') targets {num_distinct_td_offsets} offsets: "
                           f"{', '.join(fto_hex)}{'...' if num_distinct_td_offsets > 5 else ''}. Skipped by Pass 1.")
                 if local_idx not in skipped_local_indices_map: skipped_local_indices_map[local_idx] = {**cs_info, "reason": reason_amb}
                 continue
        if chosen_match:
            td_offset = chosen_match["start_index_in_target"] + chosen_match["ctx_b_len"]
            len_old = len(patch_detail_pass["old_data"]); tde_offset = td_offset + len_old
            perform_ver = (strictness_level >= 2); can_schedule = False; skip_reason_ver = ""
            if perform_ver:
                s_in_bounds = (td_offset >= 0 and tde_offset <= len(target_file_bytes_input))
                cd_target_slice = b""; dm_expected_old = False
                if not patch_detail_pass["old_data"]: dm_expected_old = True
                elif s_in_bounds:
                    cd_target_slice = target_file_bytes_input[td_offset:tde_offset]
                    dm_expected_old = (cd_target_slice == patch_detail_pass["old_data"])
                if dm_expected_old: can_schedule = True
                else: skip_reason_ver = (f"P{p_num_msg}: Verification Failed (S{strictness_level}+) at 0x{td_offset:08X}. "
                               f"Target data (len {len(cd_target_slice)}) != expected old_data (len {len_old}). Skipped by Pass 1.")
            else:
                  post_status_update(f"P{p_num_msg}: Skipping verification (S{strictness_level}) for pattern '{chosen_match['desc']}' at 0x{td_offset:08X}")
                  can_schedule = True
            if can_schedule:
                patches_to_apply_this_pass.append({"target_offset": td_offset, "len_old_data": len_old, "data_new": patch_detail_pass["new_data"],
                    "local_patch_index_this_pass": local_idx, "patch_num_original": p_num_msg, "pattern_desc": chosen_match["desc"]})
                applied_local_indices_this_pass.add(local_idx)
            elif skip_reason_ver:
                if local_idx not in skipped_local_indices_map: skipped_local_indices_map[local_idx] = {**cs_info, "reason": skip_reason_ver}
    resolve_end_time = time.time(); post_update('progress', progress_resolve_end_percent)
    post_status_update(f"Match resolution done in {resolve_end_time - resolve_start_time:.2f}s. Applying {len(patches_to_apply_this_pass)} patches...")
    patches_to_apply_this_pass.sort(key=lambda p: p["target_offset"], reverse=True)
    target_ba = bytearray(target_file_bytes_input); apply_start_time = time.time()
    apply_prog_range = progress_apply_end_percent - progress_resolve_end_percent
    for i_apply, p_info_apply in enumerate(patches_to_apply_this_pass):
        if i_apply > 0 and i_apply % 250 == 0:
            ap_done = (i_apply / len(patches_to_apply_this_pass)) if len(patches_to_apply_this_pass) > 0 else 1
            ca_prog = progress_resolve_end_percent + (apply_prog_range * ap_done)
            post_update('progress', int(ca_prog)); post_status_update(f"Applying patch {i_apply+1}/{len(patches_to_apply_this_pass)}...")
        offset = p_info_apply["target_offset"]; len_old = p_info_apply["len_old_data"]; data_new = p_info_apply["data_new"]
        l_idx_apply = p_info_apply["local_patch_index_this_pass"]; pd_pass_apply = patch_details_list_this_pass[l_idx_apply]
        p_num_apply = pd_pass_apply["patch_num_original"]
        cs_info_apply_fail = {"original_patch_index": pd_pass_apply["original_patch_index"], "patch_number": p_num_apply,
            "original_offset": pd_pass_apply["original_offset_in_file1"], "old_data_snippet": pd_pass_apply["old_data"][:16].hex(sep=' '),
            "new_data_snippet": pd_pass_apply["new_data"][:16].hex(sep=' '), "context_before": pd_pass_apply["context_before_hex"],
            "context_after": pd_pass_apply["context_after_hex"],}
        try: target_ba[offset : offset + len_old] = data_new
        except Exception as e:
            post_status_update(f"CRITICAL ERROR applying P{p_num_apply} (LocalIdx {l_idx_apply}) at 0x{offset:08X}: {e}")
            reason_crit = f"P{p_num_apply}: CRITICAL Error during final application at 0x{offset:08X}: {e}. Skipped by Pass 1."
            if l_idx_apply not in skipped_local_indices_map: skipped_local_indices_map[l_idx_apply] = {**cs_info_apply_fail, "reason": reason_crit}
            if l_idx_apply in applied_local_indices_this_pass: applied_local_indices_this_pass.remove(l_idx_apply)
    apply_end_time = time.time(); final_modified_bytes = bytes(target_ba)
    
    skipped_details_list_final = list(skipped_local_indices_map.values())
    
    applied_orig_indices = set()
    for l_idx_applied in applied_local_indices_this_pass: applied_orig_indices.add(patch_details_list_this_pass[l_idx_applied]["original_patch_index"])
    applied_count = len(applied_orig_indices)
    post_update('progress', progress_apply_end_percent)
    post_status_update(f"Application stage done in {apply_end_time - apply_start_time:.2f}s. Applied {applied_count}. Skipped {len(skipped_details_list_final)} in this pass.")
    return final_modified_bytes, applied_count, skipped_details_list_final, applied_orig_indices


# --- Patching Orchestrator ---
def apply_patches_with_multiple_passes(original_file3_bytes, all_diff_blocks_initial, initial_strictness, gui_queue):
    def post_orchestrator_update(message_type, value): gui_queue.put((message_type, value))
    def post_orchestrator_status(message):
        post_orchestrator_update('status', f"Status: Orchestrator - {message}")

    if not all_diff_blocks_initial:
        post_orchestrator_status("No differences to apply.")
        post_orchestrator_update('progress', 100)
        gui_queue.put(None)
        return original_file3_bytes, [], [] 

    all_diff_blocks_augmented = []
    for i, block in enumerate(all_diff_blocks_initial):
        augmented_block = block.copy(); augmented_block["original_patch_index"] = i; augmented_block["patch_num_original"] = i + 1
        all_diff_blocks_augmented.append(augmented_block)

    current_target_bytes = original_file3_bytes
    pass1_skipped_blocks_list = []

    P1_START, P1_SCAN_END, P1_RESOLVE_END, P1_APPLY_END = 0, 40, 60, 70
    P3_START, P3_APPLY_END = 70, 100

    post_orchestrator_status(f"Starting Pass 1 (User Strictness: {initial_strictness})...")
    pass1_start_time = time.time()
    modified_bytes_p1, p1_applied_count, p1_skipped_block_details, _ = \
        apply_patches_pure_python_search(
            current_target_bytes, all_diff_blocks_augmented, gui_queue, initial_strictness, "Pass 1",
            P1_START, P1_SCAN_END, P1_RESOLVE_END, P1_APPLY_END)
    
    pass1_skipped_blocks_list = p1_skipped_block_details
    
    p1_skipped_original_indices = {skip_info["original_patch_index"] for skip_info in pass1_skipped_blocks_list}
    current_target_bytes = modified_bytes_p1 if modified_bytes_p1 is not None else current_target_bytes
    
    pass1_end_time = time.time()
    post_orchestrator_status(f"Pass 1 finished in {pass1_end_time - pass1_start_time:.2f}s. P1 Applied: {p1_applied_count}, P1 Skipped Blocks: {len(pass1_skipped_blocks_list)}")
    
    post_orchestrator_status(f"Pass 2 (Context Search) is SKIPPED in this test version.")
    post_orchestrator_update('progress', P3_START)

    changes_for_pass3 = [chg_obj for chg_obj in all_diff_blocks_augmented 
                         if chg_obj["original_patch_index"] in p1_skipped_original_indices]
    if changes_for_pass3:
        post_orchestrator_status(f"Starting Third Pass (Byte-wise Direct Offset) for {len(changes_for_pass3)} P1-skipped patches...")
        pass3_start_time = time.time()
        target_bytearray_p3 = bytearray(current_target_bytes)
        for i_p3_block, change_obj_p3 in enumerate(changes_for_pass3):
            patch_num_p3 = change_obj_p3["patch_num_original"]
            original_f1_offset_block = change_obj_p3["original_offset"]
            old_data_f1_block = change_obj_p3["old_data_bytes"]
            new_data_f2_block = change_obj_p3["new_data_bytes"]
            current_p3_progress = P3_START + ((i_p3_block + 1) / len(changes_for_pass3)) * (P3_APPLY_END - P3_START)
            post_orchestrator_update('progress', int(current_p3_progress))
            if i_p3_block % 50 == 0:
                 post_orchestrator_status(f"P3 Byte-wise - Checking block {patch_num_p3} ({i_p3_block+1}/{len(changes_for_pass3)})...")
            len_to_process = min(len(old_data_f1_block), len(new_data_f2_block))
            target_len_p3 = len(target_bytearray_p3)
            if len_to_process == 0: continue
            for byte_idx_in_block in range(len_to_process):
                current_byte_original_f1_offset = original_f1_offset_block + byte_idx_in_block
                expected_old_byte = old_data_f1_block[byte_idx_in_block : byte_idx_in_block+1]
                intended_new_byte = new_data_f2_block[byte_idx_in_block : byte_idx_in_block+1]
                if current_byte_original_f1_offset < 0: continue
                if current_byte_original_f1_offset < target_len_p3:
                    current_byte_in_target = target_bytearray_p3[current_byte_original_f1_offset : current_byte_original_f1_offset+1]
                    if current_byte_in_target == expected_old_byte and current_byte_in_target != intended_new_byte:
                        try: target_bytearray_p3[current_byte_original_f1_offset : current_byte_original_f1_offset+1] = intended_new_byte
                        except Exception as e: post_orchestrator_status(f"P3 Byte ERROR applying at 0x{current_byte_original_f1_offset:08X}: {e}")
        current_target_bytes = bytes(target_bytearray_p3)
        pass3_end_time = time.time()
        post_orchestrator_status(f"Pass 3 finished in {pass3_end_time - pass3_start_time:.2f}s.")
    else: post_orchestrator_status("No P1-skipped patches for Pass 3 attempt.")
    
    post_orchestrator_update('progress', P3_APPLY_END)
    post_orchestrator_status(f"All patching passes complete. Pass 1 Skipped Block log is available.")
    gui_queue.put(None)
    return current_target_bytes, all_diff_blocks_augmented, pass1_skipped_blocks_list

# --- Streamlit UI ---
st.set_page_config(layout="wide")
st.title("Binary File Patcher V4.2 (Streamlit Edition)")
st.markdown("Compares File 1 & 2, applies differences to File 3. Skip log shows blocks skipped by Pass 1.")

default_file_name_map = {
    "file1_name": "File1_Original", "file2_name": "File2_Modified", "file3_name": "File3_Target"
}
for key, default_value in default_file_name_map.items():
    if key not in st.session_state: st.session_state[key] = default_value
if 'prev_file1_id' not in st.session_state: st.session_state.prev_file1_id = None
if 'prev_file2_id' not in st.session_state: st.session_state.prev_file2_id = None
if 'prev_file3_id' not in st.session_state: st.session_state.prev_file3_id = None
if 'file1_bytes' not in st.session_state: st.session_state.file1_bytes = None
if 'file2_bytes' not in st.session_state: st.session_state.file2_bytes = None
if 'original_file3_bytes' not in st.session_state: st.session_state.original_file3_bytes = None
if 'diff_blocks' not in st.session_state: st.session_state.diff_blocks = []
if 'diff_count' not in st.session_state: st.session_state.diff_count = 0
if 'final_patched_file_bytes' not in st.session_state: st.session_state.final_patched_file_bytes = None
if 'pass1_skipped_blocks_log_data' not in st.session_state: st.session_state.pass1_skipped_blocks_log_data = []
if 'last_run_summary' not in st.session_state: st.session_state.last_run_summary = {}
if 'live_log_messages' not in st.session_state: st.session_state.live_log_messages = []

col1, col2, col3 = st.columns(3)
file_upload_keys = {"file1": "uploader_f1_v42", "file2": "uploader_f2_v42", "file3": "uploader_f3_v42"}

def reset_dependent_states_v42():
    st.session_state.diff_blocks, st.session_state.diff_count = [], 0
    st.session_state.final_patched_file_bytes = None
    st.session_state.pass1_skipped_blocks_log_data = []
    st.session_state.last_run_summary = {}
    st.session_state.live_log_messages = []

with col1:
    st.header("File 1 (Original)")
    uploaded_file1 = st.file_uploader("Upload Original File", key=file_upload_keys["file1"])
    if uploaded_file1:
        new_upload = (st.session_state.prev_file1_id != uploaded_file1.file_id)
        st.session_state.file1_bytes = load_file_to_bytes_streamlit(uploaded_file1)
        st.session_state.file1_name = uploaded_file1.name
        st.session_state.prev_file1_id = uploaded_file1.file_id
        if st.session_state.file1_bytes: st.success(f"Loaded: {st.session_state.file1_name} ({len(st.session_state.file1_bytes)} bytes)")
        if new_upload: reset_dependent_states_v42()
with col2:
    st.header("File 2 (Modified)")
    uploaded_file2 = st.file_uploader("Upload Modified File", key=file_upload_keys["file2"])
    if uploaded_file2:
        new_upload = (st.session_state.prev_file2_id != uploaded_file2.file_id)
        st.session_state.file2_bytes = load_file_to_bytes_streamlit(uploaded_file2)
        st.session_state.file2_name = uploaded_file2.name
        st.session_state.prev_file2_id = uploaded_file2.file_id
        if st.session_state.file2_bytes: st.success(f"Loaded: {st.session_state.file2_name} ({len(st.session_state.file2_bytes)} bytes)")
        if new_upload: reset_dependent_states_v42()
with col3:
    st.header("File 3 (Target to Patch)")
    uploaded_file3 = st.file_uploader("Upload Target File", key=file_upload_keys["file3"])
    if uploaded_file3:
        new_upload = (st.session_state.prev_file3_id != uploaded_file3.file_id)
        st.session_state.original_file3_bytes = load_file_to_bytes_streamlit(uploaded_file3)
        st.session_state.file3_name = uploaded_file3.name
        st.session_state.prev_file3_id = uploaded_file3.file_id
        if st.session_state.original_file3_bytes: st.success(f"Loaded: {st.session_state.file3_name} ({len(st.session_state.original_file3_bytes)} bytes)")
        if new_upload: reset_dependent_states_v42()

if st.session_state.file1_bytes and st.session_state.file2_bytes and not st.session_state.diff_blocks:
    with st.spinner("Calculating differences..."):
        start_time = time.time()
        st.session_state.diff_count = count_byte_differences(st.session_state.file1_bytes, st.session_state.file2_bytes)
        st.session_state.diff_blocks = find_differences_with_context(st.session_state.file1_bytes, st.session_state.file2_bytes)
        st.info(f"Differences calculated in {time.time() - start_time:.2f}s.")
if st.session_state.file1_bytes and st.session_state.file2_bytes:
    st.subheader("Difference Summary (File 1 vs File 2)")
    st.write(f"Total Byte Differences: {st.session_state.diff_count}")
    st.write(f"Difference Blocks Found: {len(st.session_state.diff_blocks)}")
    if not st.session_state.diff_blocks and st.session_state.diff_count == 0: st.success("Files 1 and 2 are identical.")
st.divider()

st.header("Patching Controls")
strictness_level = st.slider("Pass 1 Strictness", 1, 6, 4, key="strictness_slider_main_v42")
patch_status_placeholder = st.empty()
patch_progress_placeholder = st.empty()
st.text_area("Live Log:", "\n".join(st.session_state.live_log_messages), height=200, key="live_log_display_main_v42", disabled=True)

if st.button("Apply Differences to File 3", key="apply_button_main_v42", type="primary"):
    patch_status_placeholder.info("Initiating patching...")
    patch_progress_placeholder.progress(0)
    st.session_state.final_patched_file_bytes = None
    st.session_state.pass1_skipped_blocks_log_data = []
    st.session_state.last_run_summary = {}
    st.session_state.live_log_messages = ["Log started for current run..."]

    if not (st.session_state.file1_bytes and st.session_state.file2_bytes and st.session_state.original_file3_bytes):
        patch_status_placeholder.error("Error: Please load all three files.")
    elif not st.session_state.diff_blocks and st.session_state.diff_count > 0:
        patch_status_placeholder.warning("Re-calculating differences before patching...")
        with st.spinner("Re-calculating differences..."):
             st.session_state.diff_blocks = find_differences_with_context(st.session_state.file1_bytes, st.session_state.file2_bytes)
        if not st.session_state.diff_blocks: patch_status_placeholder.info("No differences found. Nothing to apply.")
        else: patch_status_placeholder.info(f"{len(st.session_state.diff_blocks)} diff blocks found. Proceeding.")
    elif not st.session_state.diff_blocks and st.session_state.diff_count == 0:
        patch_status_placeholder.success("Files 1 and 2 are identical. No patches to apply.")
        st.session_state.final_patched_file_bytes = st.session_state.original_file3_bytes
        patch_progress_placeholder.progress(100)
    else:
        start_patch_time = time.time()
        streamlit_updater = StreamlitGuiUpdate(patch_progress_placeholder, patch_status_placeholder)

        with st.spinner(f"Applying {len(st.session_state.diff_blocks)} diff blocks... This may take some time."):
            final_bytes_after_all_passes, all_original_diffs_for_summary, pass1_skipped_blocks = \
                apply_patches_with_multiple_passes(
                    st.session_state.original_file3_bytes, st.session_state.diff_blocks,
                    strictness_level, streamlit_updater)
            
            st.session_state.final_patched_file_bytes = final_bytes_after_all_passes
            st.session_state.pass1_skipped_blocks_log_data = pass1_skipped_blocks
        
        total_patch_time = time.time() - start_patch_time
        patch_progress_placeholder.progress(100)

        total_original_diff_blocks = len(all_original_diffs_for_summary) if all_original_diffs_for_summary else 0
        p1_skipped_block_count = len(st.session_state.pass1_skipped_blocks_log_data)
        p1_applied_block_count = total_original_diff_blocks - p1_skipped_block_count
        
        total_byte_diff_vs_f3_orig = "N/A"
        if st.session_state.original_file3_bytes and st.session_state.final_patched_file_bytes:
            total_byte_diff_vs_f3_orig = count_byte_differences(st.session_state.original_file3_bytes, st.session_state.final_patched_file_bytes)
        
        st.session_state.last_run_summary = {
            "total_patch_time": total_patch_time, 
            "total_original_diff_blocks": total_original_diff_blocks,
            "p1_applied_block_count": p1_applied_block_count,
            "p1_skipped_block_count": p1_skipped_block_count,
            "total_byte_diff_vs_f3_orig": total_byte_diff_vs_f3_orig
        }
        if st.session_state.final_patched_file_bytes:
            if p1_skipped_block_count > 0:
                patch_status_placeholder.warning(f"Patching complete. Pass 1 skipped {p1_skipped_block_count} diff blocks. Time: {total_patch_time:.2f}s.")
            elif total_original_diff_blocks > 0:
                 patch_status_placeholder.success(f"Patching successfully completed! Pass 1 applied all {total_original_diff_blocks} diff blocks. Time: {total_patch_time:.2f}s.")
            else: patch_status_placeholder.success(f"Patching complete (no differences). File 3 unchanged. Time: {total_patch_time:.2f}s.")
            st.balloons()
        else: patch_status_placeholder.error("Patching process failed or resulted in no data.")
    
st.divider()
if st.session_state.final_patched_file_bytes is not None:
    st.header("Patching Results")
    summary = st.session_state.last_run_summary
    if summary:
        st.subheader("Run Summary:")
        st.markdown(f"""
        - Patching Process Time: **{summary.get('total_patch_time', 0):.2f}s**
        - Total Original Difference Blocks: **{summary.get('total_original_diff_blocks', 0)}**
        - Blocks Applied by Pass 1: **{summary.get('p1_applied_block_count', 0)}**
        - Blocks Skipped by Pass 1: **<font color='orange'>{summary.get('p1_skipped_block_count', 0)}</font>**
        - Overall Byte Difference (Final Patched File vs Original File 3): **{summary.get('total_byte_diff_vs_f3_orig', 'N/A')}**
        """, unsafe_allow_html=True)
    col_dl1, col_dl2 = st.columns(2)
    with col_dl1:
        pf_name_default = "patched_file.bin"
        pf_name = f"patched_{st.session_state.file3_name}" if st.session_state.file3_name and st.session_state.file3_name != default_file_name_map["file3_name"] else pf_name_default
        st.download_button("Download Patched File (Final)", st.session_state.final_patched_file_bytes, pf_name, "application/octet-stream", key="dl_patched_main_v42")
    
    if st.session_state.pass1_skipped_blocks_log_data or (summary and summary.get('p1_skipped_block_count', -1) == 0 and summary.get('total_original_diff_blocks',0) > 0):
        log_lines = ["Pass 1 - Skipped Blocks Log\r\n"] # Start with Windows newline
        if st.session_state.pass1_skipped_blocks_log_data:
            log_lines.append(f"The following {len(st.session_state.pass1_skipped_blocks_log_data)} difference blocks were NOT applied by Pass 1.\r\n")
            log_lines.append("Details for each skipped block:\r\n")
        elif summary and summary.get('p1_skipped_block_count', -1) == 0 and summary.get('total_original_diff_blocks',0) > 0:
            log_lines.append("Pass 1 successfully processed all difference blocks.\r\n")
        else: log_lines.append("No blocks skipped by Pass 1, or no differences to process.\r\n")
        
        log_lines.append("-" * 40 + "\r\n\r\n")
        sorted_skipped_blocks = sorted(st.session_state.pass1_skipped_blocks_log_data, key=lambda x: x.get("patch_number", 0))
        
        for skip_info in sorted_skipped_blocks:
            patch_num = skip_info.get("patch_number", "N/A")
            original_offset = skip_info.get("original_offset", -1)
            reason = skip_info.get("reason", "No reason provided.")
            old_data_snip = skip_info.get("old_data_snippet", "N/A")
            new_data_snip = skip_info.get("new_data_snippet", "N/A")
            ctx_before = skip_info.get("context_before", "N/A")
            ctx_after = skip_info.get("context_after", "N/A")

            log_lines.append(f"Skipped Original Patch #: {patch_num}\r\n")
            log_lines.append(f"  Original F1 Offset: 0x{original_offset:08X}\r\n")
            log_lines.append(f"  Reason for Skip (Pass 1): {reason}\r\n")
            log_lines.append(f"  Old Data (F1) Snippet: {old_data_snip} ...\r\n")
            log_lines.append(f"  New Data (F2) Snippet: {new_data_snip} ...\r\n")
            log_lines.append(f"  Context Before (F1): {ctx_before}\r\n")
            log_lines.append(f"  Context After (F1): {ctx_after}\r\n")
            log_lines.append("-" * 20 + "\r\n")
        
        # Join with empty string as newlines are already in list elements
        skip_log_text = "".join(log_lines) 
        # For display in Streamlit's text_area, we still use \n (browsers handle it)
        # The skip_log_text for download already has \r\n.

        with col_dl2:
            st.download_button("Download Pass 1 Skip Log", skip_log_text.encode('utf-8'), "pass1_skipped_blocks_log.txt", "text/plain", key="dl_skiplog_main_v42") # Encode for bytes
        
        if st.session_state.pass1_skipped_blocks_log_data:
            st.subheader("Pass 1 Skipped Blocks Preview (Max 20 Blocks)")
            # For display, use the text with \r\n which most modern text_areas handle or convert internally
            preview_lines_list_for_display = skip_log_text.splitlines() # This will split on \r\n or \n
            header_end_idx = 0
            for i, line_content in enumerate(preview_lines_list_for_display):
                if line_content.strip() == ("-" * 40): header_end_idx = i + 2; break
            
            preview_display_text_list = []
            current_entry_count = 0
            max_preview_entries_display = 20
            
            if header_end_idx < len(preview_lines_list_for_display):
                preview_display_text_list.extend(preview_lines_list_for_display[:header_end_idx])
                for i in range(header_end_idx, len(preview_lines_list_for_display)):
                    preview_display_text_list.append(preview_lines_list_for_display[i])
                    if preview_lines_list_for_display[i].strip() == ("-"*20): current_entry_count +=1
                    if current_entry_count >= max_preview_entries_display: break
            else: 
                preview_display_text_list = preview_lines_list_for_display[:(max_preview_entries_display*8)]

            st.text_area("Pass 1 Skip Log Preview", "\n".join(preview_display_text_list), height=300, key="skiplog_preview_main_v42", disabled=True)
            if len(sorted_skipped_blocks) > max_preview_entries_display: st.caption(f"... and {len(sorted_skipped_blocks) - max_preview_entries_display} more skipped blocks (see full log).")
        elif summary and summary.get('p1_skipped_block_count', -1) == 0 and summary.get('total_original_diff_blocks',0) > 0:
            st.success("Pass 1 Skipped Blocks Log: All blocks processed by Pass 1.")

st.sidebar.header("About")
st.sidebar.info("Binary File Patcher V4.2 (Streamlit). Skip log shows blocks skipped by Pass 1.")
st.sidebar.markdown("--- \n ### How to Use:\n1. Upload File 1 (Original Ref).\n2. Upload File 2 (Modified Ref).\n3. Upload File 3 (Target to Patch).\n4. Adjust Strictness.\n5. Click 'Apply Differences'.\n6. Review & Download results.")
