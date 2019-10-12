//
//  AppDelegate.h
//  加密方式汇总
//
//  Created by 张冲 on 2019/8/26.
//  Copyright © 2019 张冲. All rights reserved.
//

#import <UIKit/UIKit.h>
#import <CoreData/CoreData.h>

@interface AppDelegate : UIResponder <UIApplicationDelegate>

@property (strong, nonatomic) UIWindow *window;

@property (readonly, strong) NSPersistentContainer *persistentContainer;

- (void)saveContext;


@end

