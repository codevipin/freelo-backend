import { Injectable, UnauthorizedException, BadRequestException } from '@nestjs/common';
import { CognitoIdentityProviderClient, 
         SignUpCommand, 
         ConfirmSignUpCommand, 
         InitiateAuthCommand, 
         ForgotPasswordCommand, 
         ConfirmForgotPasswordCommand,
         GetUserCommand,
         AuthFlowType } from '@aws-sdk/client-cognito-identity-provider';
import { ConfigService } from '@nestjs/config';
import { RegisterDto } from '../dto/register.dto';
import { LoginDto } from '../dto/login.dto';
import { VerifyEmailDto } from '../dto/verify-email.dto';
import { ForgotPasswordDto, ConfirmForgotPasswordDto } from '../dto/forgot-password.dto';
import { RegisterResponse, LoginResponse, VerifyEmailResponse, ForgotPasswordResponse, CognitoUser } from '../interfaces/auth.interface';
import crypto from 'crypto';

export function cognitoSecretHash(username: string, clientId: string, clientSecret: string) {
  return crypto
    .createHmac('sha256', clientSecret)
    .update(username + clientId, 'utf8')
    .digest('base64');
}

@Injectable()
export class CognitoService {
  private cognitoClient: CognitoIdentityProviderClient;
  private userPoolId: string;
  private clientId: string;
  private clientSecret: string;

  constructor(private configService: ConfigService) {
    const region = this.configService.get<string>('aws.region');
    const accessKeyId = this.configService.get<string>('aws.accessKeyId');
    const secretAccessKey = this.configService.get<string>('aws.secretAccessKey');
    
    if (!region || !accessKeyId || !secretAccessKey) {
      throw new Error('AWS configuration is missing required values');
    }

    this.cognitoClient = new CognitoIdentityProviderClient({
      region,
      credentials: {
        accessKeyId,
        secretAccessKey,
      },
    });
    
    this.userPoolId = this.configService.get<string>('cognito.userPoolId') || '';
    this.clientId = this.configService.get<string>('cognito.clientId') || '';
    this.clientSecret = this.configService.get<string>('cognito.clientSecret') || '';
  }

  async register(registerDto: RegisterDto): Promise<RegisterResponse> {
    console.log('clientSecret', this.clientSecret);
    try {
      const command = new SignUpCommand({
        ClientId: this.clientId,
        Username: registerDto.email,
        Password: registerDto.password,
        UserAttributes: [
          { Name: 'name', Value: registerDto.name },
          { Name: 'email', Value: registerDto.email },
          { Name: 'phone_number', Value: registerDto.phoneNumber },
        ],
        ClientMetadata: {
          username: registerDto.email,
        },
        SecretHash: cognitoSecretHash(registerDto.email, this.clientId, this.clientSecret),
      });

      const response = await this.cognitoClient.send(command);

      return {
        message: 'User registered successfully. Please check your email for verification code.',
        userId: response.UserSub || '',
        email: registerDto.email,
        requiresVerification: !response.UserConfirmed,
      };
    } catch (error) {
      throw new BadRequestException(`Registration failed: ${error.message}`);
    }
  }

  async verifyEmail(verifyEmailDto: VerifyEmailDto): Promise<VerifyEmailResponse> {
    try {
      const command = new ConfirmSignUpCommand({
        ClientId: this.clientId,
        Username: verifyEmailDto.email,
        ConfirmationCode: verifyEmailDto.code,
        SecretHash: cognitoSecretHash(verifyEmailDto.email, this.clientId, this.clientSecret),
      });

      await this.cognitoClient.send(command);

      return {
        message: 'Email verified successfully',
        verified: true,
      };
    } catch (error) {
      throw new BadRequestException(`Email verification failed: ${error.message}`);
    }
  }

  async login(loginDto: LoginDto): Promise<LoginResponse> {
    try {
      const command = new InitiateAuthCommand({
        ClientId: this.clientId,
        AuthFlow: AuthFlowType.USER_PASSWORD_AUTH,
        AuthParameters: {
          USERNAME: loginDto.email,
          PASSWORD: loginDto.password,
          SECRET_HASH: cognitoSecretHash(loginDto.email, this.clientId, this.clientSecret),
        },
      });

      const response = await this.cognitoClient.send(command);

      if (!response.AuthenticationResult) {
        throw new UnauthorizedException('Invalid credentials');
      }

      // Get user details
      const userDetails = await this.getUserDetails(response.AuthenticationResult.AccessToken!);

      return {
        accessToken: response.AuthenticationResult.AccessToken!,
        refreshToken: response.AuthenticationResult.RefreshToken!,
        expiresIn: response.AuthenticationResult.ExpiresIn!,
        tokenType: response.AuthenticationResult.TokenType!,
        user: userDetails,
      };
    } catch (error) {
      throw new UnauthorizedException(`Login failed: ${error.message}`);
    }
  }

  async forgotPassword(forgotPasswordDto: ForgotPasswordDto): Promise<ForgotPasswordResponse> {
    try {
      const command = new ForgotPasswordCommand({
        ClientId: this.clientId,
        Username: forgotPasswordDto.email,
        SecretHash: cognitoSecretHash(forgotPasswordDto.email, this.clientId, this.clientSecret),
      });

      await this.cognitoClient.send(command);

      return {
        message: 'Password reset code sent to your email',
      };
    } catch (error) {
      throw new BadRequestException(`Forgot password failed: ${error.message}`);
    }
  }

  async confirmForgotPassword(confirmForgotPasswordDto: ConfirmForgotPasswordDto): Promise<ForgotPasswordResponse> {
    try {
      const command = new ConfirmForgotPasswordCommand({
        ClientId: this.clientId,
        Username: confirmForgotPasswordDto.email,
        ConfirmationCode: confirmForgotPasswordDto.code,
        Password: confirmForgotPasswordDto.newPassword,
        SecretHash: cognitoSecretHash(confirmForgotPasswordDto.email, this.clientId, this.clientSecret),
      });

      await this.cognitoClient.send(command);

      return {
        message: 'Password reset successfully',
      };
    } catch (error) {
      throw new BadRequestException(`Password reset failed: ${error.message}`);
    }
  }

  private async getUserDetails(accessToken: string): Promise<CognitoUser> {
    try {
      const command = new GetUserCommand({
        AccessToken: accessToken,
      });

      const response = await this.cognitoClient.send(command);

      const user: CognitoUser = {
        id: response.Username || '',
        email: '',
        name: '',
        phoneNumber: '',
        verified: false,
      };

      // Extract user attributes
      response.UserAttributes?.forEach(attr => {
        switch (attr.Name) {
          case 'email':
            user.email = attr.Value || '';
            break;
          case 'name':
            user.name = attr.Value || '';
            break;
          case 'phone_number':
            user.phoneNumber = attr.Value || '';
            break;
          case 'email_verified':
            user.verified = attr.Value === 'true';
            break;
        }
      });

      return user;
    } catch (error) {
      throw new UnauthorizedException('Failed to get user details');
    }
  }

  async verifyToken(accessToken: string): Promise<CognitoUser> {
    try {
      return await this.getUserDetails(accessToken);
    } catch (error) {
      throw new UnauthorizedException('Invalid token');
    }
  }
}
