//
//  main.cpp
//  cheat_engine_mac
//
//  Created by Akili Tulloch on 7/5/25.
//
 
#include <mach/mach.h>              // For kern_return_t, mach_port_name_t, etc.
#include <mach/mach_vm.h>           // For mach_vm_read, mach_vm_region, etc.
#include <mach/task_info.h>         // For task_info functions
#include <mach-o/dyld_images.h>     // Optional, for process images
#include <iostream>


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

void get_process_pid(char* process_name, std::vector<pid_t> &pids) {
    char command[200] = "pgrep ";
    if (strlen(process_name) + strlen(process_name) + 1 > 200) { //plus 1 for null character
        std::cerr << "Unfortunately the process name is too long." << std::endl;
    }
    strcat(command, process_name);
    
    std::cout << "Running: " << command << std::endl;
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


int main(int argc, char * argv[]) {
    
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
            
            
            vm_offset_t data;
            mach_vm_size_t size = 0;
            mach_vm_address_t address = 0;
            vm_region_basic_info_data_64_t info;
            mach_msg_type_number_t data_count = VM_REGION_BASIC_INFO_COUNT_64;
            mach_port_t object_name;
            
            while (true) {

                kern_return = mach_vm_region(target_task, &address, &size, VM_REGION_BASIC_INFO_64,
                                                    (vm_region_info_t) &info, &data_count, &object_name);
                
                if (kern_return != KERN_SUCCESS) {
                    EXIT_ON_MACH_ERROR("vm region error", kern_return, 1);
                }

                // Only scan writable memory
                if (info.protection & VM_PROT_WRITE) {
                    
                    if (mach_vm_read((mach_port_t) target_task, address, size, &data, &data_count) == KERN_SUCCESS) {
                        int* buffr = (int*)data;
                        size_t int_count = data_count / sizeof(int);

                        for (size_t i = 0; i < data_count / sizeof(int); i++) {
                            if (buffr[i] == search_value) {
                                std::cout << "Found value (dec): " << std::dec << buffr[i]
                                          << " (hex): 0x" << std::hex << buffr[i]
                                          << " at address: 0x" << std::hex
                                          << (address + (i * sizeof(int))) << std::endl;
                            }
                        }
                    }
                }
            }
            
            int new_value = 12345
            mach_vm_write(target_task, address, (vm_offset_t) new_value, sizeof(new_value)) {
            }
//            get_memory_regions(target_task, &kern_return, search_value);
        }
    
    return 0;
}
