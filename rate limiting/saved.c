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
typedef __u32 u32;
typedef __u8  u8;

int main(int argc, char** argv) {
    u32 key, next_key;
    u32 keys[MAX];
    u8 value;
    int map_fd, i, res, key_count = 0;

    map_fd = bpf_obj_get(MAP_PATH);
    if (map_fd < 0) {
        printf("map issue");
        return 1;
    }

while(1)
{
    key = -1;  //-1 start iterator
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        if (key_count >= MAX) {
            printf("key count check\n");
            close(map_fd);
            return 1;
        }
        keys[key_count++] = next_key;
        key = next_key;
    }

    for (i = 0; i < key_count; i++) 
    {
        res = bpf_map_lookup_elem(map_fd, &keys[i], &value);
        if (res < 0) 
            printf("lookup failed\n");
       
        else 
        {
            printf("key= %u before= %u\n", keys[i], value);
            u8 new_val = 0;
            if (bpf_map_update_elem(map_fd, &keys[i], &new_val, BPF_ANY) != 0) 
                printf("failed for update=%u\n",keys[i]);
            else printf("safely updated to 0\n");

            //confirmation
            //res = bpf_map_lookup_elem(map_fd, &keys[i], &value);
            //if (res == 0) 
              //  printf("value=0\n");
             
        }
    }
    sleep(10);
}
    close(map_fd);
    return 0;
}

