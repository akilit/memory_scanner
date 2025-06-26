#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <iostream>
#include <vector>
#include <string>
#include <unistd.h>

// prototypes:

#define EXIT_ON_MACH_ERROR(msg, kr, retval) \
    if (kr != KERN_SUCCESS) { \
        std::cerr << msg << ": " << mach_error_string(retval) << std::endl; \
        std::exit(retval); \
    }


mach_port_name_t get_task_for_pid(const pid_t &pid, kern_return_t *krn_return) {
    mach_port_name_t target_task;

    *krn_return = task_for_pid(mach_task_self(), pid, &target_task);
    
    EXIT_ON_MACH_ERROR("task_for_pid", *krn_return, 1);

    // if (*krn_return != KERN_SUCCESS) {
    //     std::cerr << "Failed to get task for PID " << pid << std::endl;
    //     return KERN_INVALID_TASK;
    // }
    std::cout << "Recieved task for PID: " << pid << std::endl;
    return target_task;
}


void get_memory_regions(const mach_port_name_t &target_task, kern_return_t *krn_return, const int &search_value) {
    
    mach_vm_address_t                   upper_limit = 0x7FFFFFFFFFFFFFFF;
    mach_vm_address_t                   lower_limit = 0x000000000000000; // aka the lower limit
    mach_vm_size_t                      region_size = 0;
    natural_t                           depth = 0;
    vm_region_submap_info_data_64_t     info = { 0 };
    mach_msg_type_number_t              infoCount = VM_REGION_SUBMAP_INFO_COUNT_64;


    while (lower_limit <= upper_limit) {
        *krn_return = mach_vm_region_recurse(target_task, &lower_limit, &region_size, &depth, (vm_region_recurse_info_t) &info, &infoCount);
        std::cout << "krn_return:" << *krn_return << std::endl;
        
         std::cout << "start address: " << std::hex << lower_limit << std::hex << std::endl;
         std::cout << "size, end address:" << std::hex << region_size << std::hex << ", " << std::hex << lower_limit+region_size << std::hex << std::endl;

        unsigned char mem_buffer[region_size]; // NEED A DELETE

        EXIT_ON_MACH_ERROR("mach_vm_region_recurse", *krn_return, 1);
        // if (*krn_return != KERN_SUCCESS) {
        //     std::cerr << "Failed to find memory region: " << *krn_return << std::endl;
        //     break;
        // } 
        
        if (info.is_submap) {
            depth++;
        } else { // now have info for one region to scan
            // we use a buffer to hold buffer memory region data and scan buffer. bc direct read of memory is prohibitied... (to some an i think)
            vm_offset_t data = 0;
            mach_msg_type_number_t dataCnt = 0;

            *krn_return = mach_vm_read(target_task, lower_limit, region_size, &data, &dataCnt); // data being 
            if (!(info.protection & VM_PROT_READ)) {
                lower_limit += region_size;
                continue;
            }
            if (*krn_return != KERN_SUCCESS) {
                std::cerr << "Failed to read memory at 0x" << std::hex << lower_limit << ": " << mach_error_string(*krn_return) << std::dec << std::endl;
                lower_limit += region_size;
                continue;
            }


            memcpy(mem_buffer, (const void *) data, region_size);

            //int serves as index scanning buffer
            int buffer_index = 0;
            while (buffer_index < region_size - sizeof(uint32_t)) {
                int* current_value = (int*)(mem_buffer + buffer_index);
                if (search_value == *current_value) {
                    std::cout << "Value " << search_value << "found at address 0x" << std::hex << lower_limit + buffer_index << std::hex << std::endl;
                }
                buffer_index += sizeof(uint32_t);
            }

            lower_limit = lower_limit + region_size;
        }
    }
}

void get_process_pid(char* process_name, std::vector<pid_t> &pids) {

    char command[200] = "pgrep ";
    if (strlen(process_name) + strlen(process_name) + 1 > 200) { // plus one for null character
        std::cerr << "Unfortunately the process name is too long." << std::endl;
    }
    strcat(command, process_name);
    
    std::cout << "running: " << command << std::endl;
    FILE *fp = popen(command, "r");
    if (fp == nullptr) {
        std::cerr << "Failed to run 'pgrep' to find process ID" << std::endl; 
    }

    char buffer[30];
    while (fgets(buffer, 30, fp) != NULL) {
        pids.push_back(atoi(buffer));
    }

    for (size_t i = 0; i < pids.size(); i++) {
        std::cout << pids[i] << std::endl;
    }
    pclose(fp);

}

int main(int argc, char* argv[]) {

    kern_return_t           kern_return = 0;
    mach_port_name_t        target_task;
    std::vector<pid_t>      pids_list; // vector collecting our PID's. will use vectors because we need to scan multiple instances of a process (each with a different pid)
    int                     search_value;
    

    if (argc < 2) {
        std::cout << "Please enter a process name (use activity monitor). call script format: './cheatengine <target_process_name>'" << std::endl;
        return 0;
    }
    if (argc > 2) {
        std::cout << "Passed too many arguments. call script format: './cheatengine <target_process_name>'" << std::endl;
        return 0;
    }


    char* process_name = argv[1]; // process_name pointer pointing to user inputted process name (be careful for attacks/injections!)
    get_process_pid(process_name, pids_list); // fills the list with PID values for the process the user selected


    std::cout << "Enter an (int) value to search for: " << std::endl;
    std::cin >> search_value;

    // loop through target_tasks.
    for (int pid_idx = 0; pid_idx < pids_list.size(); pid_idx++) {
        
        target_task = get_task_for_pid(pids_list[pid_idx], &kern_return);

        get_memory_regions(target_task, &kern_return, search_value);

    }
}
