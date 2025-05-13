#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
//huge overhead... insanely inefficient, but works.
#define MAP_PATH "/sys/fs/bpf/current_packets"  
#define MAX 2048

int main(int argc, char** argv) {
    __u32 key, next_key;
    __u32 keys[MAX];
    __u8 value;
    int map_fd, i, res, key_count = 0;

    map_fd = bpf_obj_get(MAP_PATH);
    if (map_fd < 0) {
        return 1;
    }

while(1)
{
    key = -1;  //-1 start iterator
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        if (key_count >= MAX) {
            close(map_fd);
            return 1;
        }
        keys[key_count++] = next_key;
        key = next_key;
    }

    for (i = 0; i < key_count; i++) 
    {
        res = bpf_map_lookup_elem(map_fd, &keys[i], &value);
       
            __u8 new_val = 0;
            bpf_map_update_elem(map_fd, &keys[i], &new_val, BPF_ANY); 
             
        
    }
    sleep(30);
}
    close(map_fd);
    return 0;
}

