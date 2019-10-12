//
//  ViewController.m
//  加密方式汇总
//
//  Created by 张冲 on 2019/8/26.
//  Copyright © 2019 张冲. All rights reserved.
//

#import "ViewController.h"
#import "SecretViewController.h"
@interface ViewController ()
@property (nonatomic,weak) UIStoryboard *storyBoard;
@property (nonatomic,weak)SecretViewController *secretVC;
@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    _storyBoard = [UIStoryboard storyboardWithName:@"Main" bundle:[NSBundle mainBundle]];
    self.secretVC = [_storyBoard instantiateViewControllerWithIdentifier:@"secretVC"];
    // Do any additional setup after loading the view.
}

-(void)prepareForSegue:(UIStoryboardSegue *)segue sender:(id)sender{
    if ([segue.identifier isEqualToString:@"Base64"]) {
        SecretViewController *secret = segue.destinationViewController;
        secret.secretType = Base64Type;
    }else if ([segue.identifier isEqualToString:@"MD5"]){
        SecretViewController *secret = segue.destinationViewController;
        secret.secretType = MD5Type;
    }else if ([segue.identifier isEqualToString:@"AES"]){
        SecretViewController *secret = segue.destinationViewController;
        secret.secretType = AESType;
    }else if ([segue.identifier isEqualToString:@"RSA"]){
        SecretViewController *secret = segue.destinationViewController;
        secret.secretType = RSAType;
    }
}

@end
