import { Controller, Get, UseGuards, Request } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { AppService } from './app.service';
import { JwtAuthGuard } from './auth/guards/jwt-auth.guard';
import { CognitoUser } from './auth/interfaces/auth.interface';
import { Public } from './auth/decorators/public.decorator';

@ApiTags('freelo')
@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Public()
  @Get()
  @ApiOperation({ summary: 'Get hello message' })
  @ApiResponse({ 
    status: 200, 
    description: 'Returns a hello message',
    schema: {
      type: 'string',
      example: 'Hello World!'
    }
  })
  getHello(): string {
    return this.appService.getHello();
  }

  @Get('profile')
  @UseGuards(JwtAuthGuard)
  @ApiTags('User Profile')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get user profile (Protected endpoint)' })
  @ApiResponse({
    status: 200,
    description: 'User profile retrieved successfully',
    schema: {
      example: {
        message: 'Profile retrieved successfully',
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
  @ApiResponse({ status: 401, description: 'Unauthorized - invalid or missing token' })
  getProfile(@Request() req: any): { message: string; user: CognitoUser } {
    return {
      message: 'Profile retrieved successfully',
      user: req.user,
    };
  }
}
