import { Controller, Post, Body, HttpCode, HttpStatus } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { CognitoService } from './services/cognito.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { VerifyEmailDto } from './dto/verify-email.dto';
import { ForgotPasswordDto, ConfirmForgotPasswordDto } from './dto/forgot-password.dto';
import { Public } from './decorators/public.decorator';
import { RegisterResponse, LoginResponse, VerifyEmailResponse, ForgotPasswordResponse } from './interfaces/auth.interface';

@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
  constructor(private readonly cognitoService: CognitoService) {}

  @Public()
  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Register a new user' })
  @ApiResponse({
    status: 201,
    description: 'User registered successfully',
    schema: {
      example: {
        message: 'User registered successfully. Please check your email for verification code.',
        userId: 'uuid-string',
        email: 'user@example.com',
        requiresVerification: true,
      },
    },
  })
  @ApiResponse({ status: 400, description: 'Bad request - validation failed' })
  async register(@Body() registerDto: RegisterDto): Promise<RegisterResponse> {
    return this.cognitoService.register(registerDto);
  }

  @Public()
  @Post('verify-email')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Verify user email with code' })
  @ApiResponse({
    status: 200,
    description: 'Email verified successfully',
    schema: {
      example: {
        message: 'Email verified successfully',
        verified: true,
      },
    },
  })
  @ApiResponse({ status: 400, description: 'Bad request - invalid verification code' })
  async verifyEmail(@Body() verifyEmailDto: VerifyEmailDto): Promise<VerifyEmailResponse> {
    return this.cognitoService.verifyEmail(verifyEmailDto);
  }

  @Public()
  @Post('login')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Login user with email and password' })
  @ApiResponse({
    status: 200,
    description: 'Login successful',
    schema: {
      example: {
        accessToken: 'jwt-token',
        refreshToken: 'refresh-token',
        expiresIn: 3600,
        tokenType: 'Bearer',
        user: {
          id: 'user-id',
          email: 'user@example.com',
          name: 'John Doe',
          phoneNumber: '+1234567890',
          verified: true,
        },
      },
    },
  })
  @ApiResponse({ status: 401, description: 'Unauthorized - invalid credentials' })
  async login(@Body() loginDto: LoginDto): Promise<LoginResponse> {
    return this.cognitoService.login(loginDto);
  }

  @Public()
  @Post('forgot-password')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Send forgot password code to email' })
  @ApiResponse({
    status: 200,
    description: 'Password reset code sent to email',
    schema: {
      example: {
        message: 'Password reset code sent to your email',
      },
    },
  })
  @ApiResponse({ status: 400, description: 'Bad request - user not found' })
  async forgotPassword(@Body() forgotPasswordDto: ForgotPasswordDto): Promise<ForgotPasswordResponse> {
    return this.cognitoService.forgotPassword(forgotPasswordDto);
  }

  @Public()
  @Post('confirm-forgot-password')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Confirm forgot password with code and new password' })
  @ApiResponse({
    status: 200,
    description: 'Password reset successfully',
    schema: {
      example: {
        message: 'Password reset successfully',
      },
    },
  })
  @ApiResponse({ status: 400, description: 'Bad request - invalid code or password' })
  async confirmForgotPassword(@Body() confirmForgotPasswordDto: ConfirmForgotPasswordDto): Promise<ForgotPasswordResponse> {
    return this.cognitoService.confirmForgotPassword(confirmForgotPasswordDto);
  }
}
