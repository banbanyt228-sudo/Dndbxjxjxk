#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <AuthenticationServices/AuthenticationServices.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import "fishhook.h"

#define ERR_SEC_MISSING_ENTITLEMENT -34018

static NSString *const kClientId = @"00000000441cc96b"; // Nintendo Switch Client ID

#pragma mark - Локальное хранилище данных

static NSString *GetStoragePath(void) {
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    return [docs stringByAppendingPathComponent:@"mc_keychain.plist"];
}

static NSMutableDictionary *LoadFallbackStorage(void) {
    NSMutableDictionary *dict = [NSMutableDictionary dictionaryWithContentsOfFile:GetStoragePath()];
    return dict ? dict : [NSMutableDictionary dictionary];
}

static void SaveFallbackStorage(NSDictionary *dict) {
    [dict writeToFile:GetStoragePath() atomically:YES];
}

#pragma mark - Хуки Security.framework (Keychain)

typedef OSStatus (*SecItemAdd_t)(CFDictionaryRef attributes, CFTypeRef *result);
typedef OSStatus (*SecItemCopyMatching_t)(CFDictionaryRef query, CFTypeRef *result);
typedef OSStatus (*SecItemUpdate_t)(CFDictionaryRef query, CFDictionaryRef attributesToUpdate);
typedef OSStatus (*SecItemDelete_t)(CFDictionaryRef query);

static SecItemAdd_t orig_SecItemAdd;
static SecItemCopyMatching_t orig_SecItemCopyMatching;
static SecItemUpdate_t orig_SecItemUpdate;
static SecItemDelete_t orig_SecItemDelete;

static CFDictionaryRef CleanAccessGroup(CFDictionaryRef dict) {
    if (!dict) return NULL;
    NSMutableDictionary *cleaned = [(__bridge NSDictionary *)dict mutableCopy];
    [cleaned removeObjectForKey:(__bridge id)kSecAttrAccessGroup];
    return (__bridge_retained CFDictionaryRef)cleaned;
}

static OSStatus hooked_SecItemAdd(CFDictionaryRef attributes, CFTypeRef *result) {
    CFDictionaryRef cleaned = CleanAccessGroup(attributes);
    OSStatus status = orig_SecItemAdd(cleaned ? cleaned : attributes, result);
    if (cleaned) CFRelease(cleaned);

    if (status == ERR_SEC_MISSING_ENTITLEMENT) {
        NSDictionary *dict = (__bridge NSDictionary *)attributes;
        NSString *key = dict[(__bridge id)kSecAttrAccount] ?: dict[(__bridge id)kSecAttrService] ?: @"mc_auth_key";
        NSMutableDictionary *storage = LoadFallbackStorage();
        storage[key] = dict[(__bridge id)kSecValueData];
        SaveFallbackStorage(storage);
        return errSecSuccess;
    }
    return status;
}

static OSStatus hooked_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    CFDictionaryRef cleaned = CleanAccessGroup(query);
    OSStatus status = orig_SecItemCopyMatching(cleaned ? cleaned : query, result);
    if (cleaned) CFRelease(cleaned);

    if (status == ERR_SEC_MISSING_ENTITLEMENT || status == errSecItemNotFound) {
        NSDictionary *dict = (__bridge NSDictionary *)query;
        NSString *key = dict[(__bridge id)kSecAttrAccount] ?: dict[(__bridge id)kSecAttrService] ?: @"mc_auth_key";
        NSMutableDictionary *storage = LoadFallbackStorage();
        NSData *data = storage[key];

        if (data && result) {
            if ([dict[(__bridge id)kSecReturnData] boolValue]) {
                *result = (__bridge_retained CFTypeRef)data;
                return errSecSuccess;
            }
        }
        return errSecItemNotFound;
    }
    return status;
}

static OSStatus hooked_SecItemUpdate(CFDictionaryRef query, CFDictionaryRef attributesToUpdate) {
    CFDictionaryRef cq = CleanAccessGroup(query);
    CFDictionaryRef ca = CleanAccessGroup(attributesToUpdate);
    OSStatus status = orig_SecItemUpdate(cq ? cq : query, ca ? ca : attributesToUpdate);
    if (cq) CFRelease(cq);
    if (ca) CFRelease(ca);

    if (status == ERR_SEC_MISSING_ENTITLEMENT) {
        return hooked_SecItemAdd(attributesToUpdate, NULL);
    }
    return status;
}

static OSStatus hooked_SecItemDelete(CFDictionaryRef query) {
    CFDictionaryRef cq = CleanAccessGroup(query);
    OSStatus status = orig_SecItemDelete(cq ? cq : query);
    if (cq) CFRelease(cq);

    NSMutableDictionary *storage = LoadFallbackStorage();
    [storage removeAllObjects];
    SaveFallbackStorage(storage);
    return errSecSuccess;
}

#pragma mark - Device Code Flow (Вход с другого устройства)

static UIBackgroundTaskIdentifier bgTask = UIBackgroundTaskInvalid;

static UIViewController *GetTopViewController(void) {
    UIWindow *window = nil;
    for (UIWindow *w in [UIApplication sharedApplication].windows) {
        if (w.isKeyWindow) { window = w; break; }
    }
    if (!window) {
        window = [UIApplication sharedApplication].keyWindow;
    }
    UIViewController *top = window.rootViewController;
    while (top.presentedViewController) {
        top = top.presentedViewController;
    }
    return top;
}

static void CleanupBackgroundTask(void) {
    if (bgTask != UIBackgroundTaskInvalid) {
        [[UIApplication sharedApplication] endBackgroundTask:bgTask];
        bgTask = UIBackgroundTaskInvalid;
    }
    dispatch_async(dispatch_get_main_queue(), ^{
        [UIApplication sharedApplication].idleTimerDisabled = NO;
    });
}

static void PollForToken(NSString *deviceCode, NSInteger interval, UIAlertController *waitingAlert) {
    bgTask = [[UIApplication sharedApplication] beginBackgroundTaskWithName:@"MCAuthPoll" expirationHandler:^{
        CleanupBackgroundTask();
    }];

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        BOOL completed = NO;
        NSURL *tokenUrl = [NSURL URLWithString:@"https://login.microsoftonline.com/consumers/oauth2/v2.0/token"];

        while (!completed && waitingAlert.presentingViewController != nil) {
            [NSThread sleepForTimeInterval:(interval > 0 ? interval : 5)];

            NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:tokenUrl];
            req.HTTPMethod = @"POST";
            [req setValue:@"application/x-www-form-urlencoded" forHTTPHeaderField:@"Content-Type"];

            NSString *body = [NSString stringWithFormat:
                @"grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=%@&device_code=%@",
                kClientId, deviceCode];
            req.HTTPBody = [body dataUsingEncoding:NSUTF8StringEncoding];

            dispatch_semaphore_t sem = dispatch_semaphore_create(0);
            [[[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(NSData *data, NSURLResponse *res, NSError *err) {
                if (data) {
                    NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
                    if (json[@"access_token"]) {
                        completed = YES;
                        
                        NSMutableDictionary *storage = LoadFallbackStorage();
                        storage[@"msa_token"] = [json[@"access_token"] dataUsingEncoding:NSUTF8StringEncoding];
                        if (json[@"refresh_token"]) {
                            storage[@"refresh_token"] = [json[@"refresh_token"] dataUsingEncoding:NSUTF8StringEncoding];
                        }
                        SaveFallbackStorage(storage);

                        dispatch_async(dispatch_get_main_queue(), ^{
                            [waitingAlert dismissViewControllerAnimated:YES completion:^{
                                UIAlertController *successAlert = [UIAlertController alertControllerWithTitle:@"Успешно!"
                                    message:@"Вход выполнен. Перезапустите Minecraft для обновления профиля."
                                    preferredStyle:UIAlertControllerStyleAlert];
                                [successAlert addAction:[UIAlertAction actionWithTitle:@"ОК" style:UIAlertActionStyleDefault handler:nil]];
                                [GetTopViewController() presentViewController:successAlert animated:YES completion:nil];
                            }];
                        });
                        CleanupBackgroundTask();
                    }
                }
                dispatch_semaphore_signal(sem);
            }] resume];
            dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
        }
    });
}

static void StartDeviceCodeFlow(void) {
    NSURL *url = [NSURL URLWithString:@"https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode"];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    req.HTTPMethod = @"POST";
    [req setValue:@"application/x-www-form-urlencoded" forHTTPHeaderField:@"Content-Type"];

    NSString *body = [NSString stringWithFormat:@"client_id=%@&scope=XboxLive.signin%%20offline_access", kClientId];
    req.HTTPBody = [body dataUsingEncoding:NSUTF8StringEncoding];

    [[[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(NSData *data, NSURLResponse *res, NSError *err) {
        if (!data) return;
        NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
        NSString *userCode = json[@"user_code"];
        NSString *deviceCode = json[@"device_code"];
        NSInteger interval = [json[@"interval"] integerValue];

        if (!userCode || !deviceCode) return;

        dispatch_async(dispatch_get_main_queue(), ^{
            [UIApplication sharedApplication].idleTimerDisabled = YES;
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <AuthenticationServices/AuthenticationServices.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import "fishhook.h"

#define ERR_SEC_MISSING_ENTITLEMENT -34018

static NSString *const kClientId = @"00000000441cc96b"; // Nintendo Switch Client ID

#pragma mark - Локальное хранилище данных

static NSString *GetStoragePath(void) {
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    return [docs stringByAppendingPathComponent:@"mc_keychain.plist"];
}

static NSMutableDictionary *LoadFallbackStorage(void) {
    NSMutableDictionary *dict = [NSMutableDictionary dictionaryWithContentsOfFile:GetStoragePath()];
    return dict ? dict : [NSMutableDictionary dictionary];
}

static void SaveFallbackStorage(NSDictionary *dict) {
    [dict writeToFile:GetStoragePath() atomically:YES];
}

#pragma mark - Хуки Security.framework (Keychain)

typedef OSStatus (*SecItemAdd_t)(CFDictionaryRef attributes, CFTypeRef *result);
typedef OSStatus (*SecItemCopyMatching_t)(CFDictionaryRef query, CFTypeRef *result);
typedef OSStatus (*SecItemUpdate_t)(CFDictionaryRef query, CFDictionaryRef attributesToUpdate);
typedef OSStatus (*SecItemDelete_t)(CFDictionaryRef query);

static SecItemAdd_t orig_SecItemAdd;
static SecItemCopyMatching_t orig_SecItemCopyMatching;
static SecItemUpdate_t orig_SecItemUpdate;
static SecItemDelete_t orig_SecItemDelete;

static CFDictionaryRef CleanAccessGroup(CFDictionaryRef dict) {
    if (!dict) return NULL;
    NSMutableDictionary *cleaned = [(__bridge NSDictionary *)dict mutableCopy];
    [cleaned removeObjectForKey:(__bridge id)kSecAttrAccessGroup];
    return (__bridge_retained CFDictionaryRef)cleaned;
}

static OSStatus hooked_SecItemAdd(CFDictionaryRef attributes, CFTypeRef *result) {
    CFDictionaryRef cleaned = CleanAccessGroup(attributes);
    OSStatus status = orig_SecItemAdd(cleaned ? cleaned : attributes, result);
    if (cleaned) CFRelease(cleaned);

    if (status == ERR_SEC_MISSING_ENTITLEMENT) {
        NSDictionary *dict = (__bridge NSDictionary *)attributes;
        NSString *key = dict[(__bridge id)kSecAttrAccount] ?: dict[(__bridge id)kSecAttrService] ?: @"mc_auth_key";
        NSMutableDictionary *storage = LoadFallbackStorage();
        storage[key] = dict[(__bridge id)kSecValueData];
        SaveFallbackStorage(storage);
        return errSecSuccess;
    }
    return status;
}

static OSStatus hooked_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    CFDictionaryRef cleaned = CleanAccessGroup(query);
    OSStatus status = orig_SecItemCopyMatching(cleaned ? cleaned : query, result);
    if (cleaned) CFRelease(cleaned);

    if (status == ERR_SEC_MISSING_ENTITLEMENT || status == errSecItemNotFound) {
        NSDictionary *dict = (__bridge NSDictionary *)query;
        NSString *key = dict[(__bridge id)kSecAttrAccount] ?: dict[(__bridge id)kSecAttrService] ?: @"mc_auth_key";
        NSMutableDictionary *storage = LoadFallbackStorage();
        NSData *data = storage[key];

        if (data && result) {
            if ([dict[(__bridge id)kSecReturnData] boolValue]) {
                *result = (__bridge_retained CFTypeRef)data;
                return errSecSuccess;
            }
        }
        return errSecItemNotFound;
    }
    return status;
}

static OSStatus hooked_SecItemUpdate(CFDictionaryRef query, CFDictionaryRef attributesToUpdate) {
    CFDictionaryRef cq = CleanAccessGroup(query);
    CFDictionaryRef ca = CleanAccessGroup(attributesToUpdate);
    OSStatus status = orig_SecItemUpdate(cq ? cq : query, ca ? ca : attributesToUpdate);
    if (cq) CFRelease(cq);
    if (ca) CFRelease(ca);

    if (status == ERR_SEC_MISSING_ENTITLEMENT) {
        return hooked_SecItemAdd(attributesToUpdate, NULL);
    }
    return status;
}

static OSStatus hooked_SecItemDelete(CFDictionaryRef query) {
    CFDictionaryRef cq = CleanAccessGroup(query);
    OSStatus status = orig_SecItemDelete(cq ? cq : query);
    if (cq) CFRelease(cq);

    NSMutableDictionary *storage = LoadFallbackStorage();
    [storage removeAllObjects];
    SaveFallbackStorage(storage);
    return errSecSuccess;
}

#pragma mark - Device Code Flow (Вход с другого устройства)

static UIBackgroundTaskIdentifier bgTask;

static UIViewController *GetTopViewController(void) {
    UIWindow *window = nil;
    NSArray<UIWindow *> *windows = [UIApplication sharedApplication].windows;
    for (UIWindow *w in windows) {
        if (w.isKeyWindow) {
            window = w;
            break;
        }
    }
    if (!window && windows.count > 0) {
        window = windows.firstObject;
    }
    UIViewController *top = window.rootViewController;
    while (top.presentedViewController) {
        top = top.presentedViewController;
    }
    return top;
}

static void CleanupBackgroundTask(void) {
    if (bgTask != UIBackgroundTaskInvalid) {
        [[UIApplication sharedApplication] endBackgroundTask:bgTask];
        bgTask = UIBackgroundTaskInvalid;
    }
    dispatch_async(dispatch_get_main_queue(), ^{
        [UIApplication sharedApplication].idleTimerDisabled = NO;
    });
}

static void PollForToken(NSString *deviceCode, NSInteger interval, UIAlertController *waitingAlert) {
    bgTask = [[UIApplication sharedApplication] beginBackgroundTaskWithName:@"MCAuthPoll" expirationHandler:^{
        CleanupBackgroundTask();
    }];

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        __block BOOL completed = NO;
        NSURL *tokenUrl = [NSURL URLWithString:@"https://login.microsoftonline.com/consumers/oauth2/v2.0/token"];

        while (!completed && waitingAlert.presentingViewController != nil) {
            [NSThread sleepForTimeInterval:(interval > 0 ? interval : 5)];

            NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:tokenUrl];
            req.HTTPMethod = @"POST";
            [req setValue:@"application/x-www-form-urlencoded" forHTTPHeaderField:@"Content-Type"];

            NSString *body = [NSString stringWithFormat:
                @"grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=%@&device_code=%@",
                kClientId, deviceCode];
            req.HTTPBody = [body dataUsingEncoding:NSUTF8StringEncoding];

            dispatch_semaphore_t sem = dispatch_semaphore_create(0);
            [[[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(NSData *data, NSURLResponse *res, NSError *err) {
                if (data) {
                    NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
                    if (json[@"access_token"]) {
                        completed = YES;
                        
                        NSMutableDictionary *storage = LoadFallbackStorage();
                        storage[@"msa_token"] = [json[@"access_token"] dataUsingEncoding:NSUTF8StringEncoding];
                        if (json[@"refresh_token"]) {
                            storage[@"refresh_token"] = [json[@"refresh_token"] dataUsingEncoding:NSUTF8StringEncoding];
                        }
                        SaveFallbackStorage(storage);

                        dispatch_async(dispatch_get_main_queue(), ^{
                            [waitingAlert dismissViewControllerAnimated:YES completion:^{
                                UIAlertController *successAlert = [UIAlertController alertControllerWithTitle:@"Успешно!"
                                    message:@"Вход выполнен. Перезапустите Minecraft для обновления профиля."
                                    preferredStyle:UIAlertControllerStyleAlert];
                                [successAlert addAction:[UIAlertAction actionWithTitle:@"ОК" style:UIAlertActionStyleDefault handler:nil]];
                                [GetTopViewController() presentViewController:successAlert animated:YES completion:nil];
                            }];
                        });
                        CleanupBackgroundTask();
                    }
                }
                dispatch_semaphore_signal(sem);
            }] resume];
            dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
        }
    });
}

static void StartDeviceCodeFlow(void) {
    NSURL *url = [NSURL URLWithString:@"https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode"];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    req.HTTPMethod = @"POST";
    [req setValue:@"application/x-www-form-urlencoded" forHTTPHeaderField:@"Content-Type"];

    NSString *body = [NSString stringWithFormat:@"client_id=%@&scope=XboxLive.signin%%20offline_access", kClientId];
    req.HTTPBody = [body dataUsingEncoding:NSUTF8StringEncoding];

    [[[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(NSData *data, NSURLResponse *res, NSError *err) {
        if (!data) return;
        NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
        NSString *userCode = json[@"user_code"];
        NSString *deviceCode = json[@"device_code"];
        NSInteger interval = [json[@"interval"] integerValue];

        if (!userCode || !deviceCode) return;

        dispatch_async(dispatch_get_main_queue(), ^{
            [UIApplication sharedApplication].idleTimerDisabled = YES;

            NSString *message = [NSString stringWithFormat:
                @"1. Откройте на другом устройстве:\nmicrosoft.com/link\n\n"
                @"2. Введите код:\n%@\n\n"
                @"Не сворачивайте игру, она ожидает подтверждения...",
                userCode];

            UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Вход Microsoft"
                message:message
                preferredStyle:UIAlertControllerStyleAlert];

            [alert addAction:[UIAlertAction actionWithTitle:@"Отмена" style:UIAlertActionStyleCancel handler:^(UIAlertAction * _Nonnull action) {
                CleanupBackgroundTask();
            }]];

            [GetTopViewController() presentViewController:alert animated:YES completion:^{
                PollForToken(deviceCode, interval, alert);
            }];
        });
    }] resume];
}

#pragma mark - Перехват вызова входа

@interface ASWebAuthenticationSession (Hook)
@end

@implementation ASWebAuthenticationSession (Hook)

+ (void)load {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        Class cls = [ASWebAuthenticationSession class];
        Method orig = class_getInstanceMethod(cls, @selector(start));
        Method swizz = class_getInstanceMethod(cls, @selector(hooked_start));
        if (orig && swizz) {
            method_exchangeImplementations(orig, swizz);
        }
    });
}

- (BOOL)hooked_start {
    dispatch_async(dispatch_get_main_queue(), ^{
        StartDeviceCodeFlow();
    });
    return NO;
}

@end

#pragma mark - Регистрация хуков

__attribute__((constructor))
static void initFix(void) {
    bgTask = UIBackgroundTaskInvalid;

    orig_SecItemAdd = (SecItemAdd_t)dlsym(RTLD_DEFAULT, "SecItemAdd");
    orig_SecItemCopyMatching = (SecItemCopyMatching_t)dlsym(RTLD_DEFAULT, "SecItemCopyMatching");
    orig_SecItemUpdate = (SecItemUpdate_t)dlsym(RTLD_DEFAULT, "SecItemUpdate");
    orig_SecItemDelete = (SecItemDelete_t)dlsym(RTLD_DEFAULT, "SecItemDelete");

    struct rebinding rebindings[] = {
        {"SecItemAdd", (void *)hooked_SecItemAdd, (void **)&orig_SecItemAdd},
        {"SecItemCopyMatching", (void *)hooked_SecItemCopyMatching, (void **)&orig_SecItemCopyMatching},
        {"SecItemUpdate", (void *)hooked_SecItemUpdate, (void **)&orig_SecItemUpdate},
        {"SecItemDelete", (void *)hooked_SecItemDelete, (void **)&orig_SecItemDelete}
    };
    rebind_symbols(rebindings, 4);
}
   method_exchangeImplementations(orig, swizz);
        }
    });
}

- (BOOL)hooked_start {
    dispatch_async(dispatch_get_main_queue(), ^{
        StartDeviceCodeFlow();
    });
    return NO;
}

@end

#pragma mark - Регистрация хуков

__attribute__((constructor))
static void initFix(void) {
    orig_SecItemAdd = (SecItemAdd_t)dlsym(RTLD_DEFAULT, "SecItemAdd");
    orig_SecItemCopyMatching = (SecItemCopyMatching_t)dlsym(RTLD_DEFAULT, "SecItemCopyMatching");
    orig_SecItemUpdate = (SecItemUpdate_t)dlsym(RTLD_DEFAULT, "SecItemUpdate");
    orig_SecItemDelete = (SecItemDelete_t)dlsym(RTLD_DEFAULT, "SecItemDelete");

    struct rebinding rebindings[] = {
        {"SecItemAdd", (void *)hooked_SecItemAdd, (void **)&orig_SecItemAdd},
        {"SecItemCopyMatching", (void *)hooked_SecItemCopyMatching, (void **)&orig_SecItemCopyMatching},
        {"SecItemUpdate", (void *)hooked_SecItemUpdate, (void **)&orig_SecItemUpdate},
        {"SecItemDelete", (void *)hooked_SecItemDelete, (void **)&orig_SecItemDelete}
    };
    rebind_symbols(rebindings, 4);
}
