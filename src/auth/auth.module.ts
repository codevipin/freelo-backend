import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AuthController } from './auth.controller';
import { CognitoService } from './services/cognito.service';
import { JwtAuthGuard } from './guards/jwt-auth.guard';

@Module({
  imports: [
    ConfigModule,
  ],
  controllers: [AuthController],
  providers: [CognitoService, JwtAuthGuard],
  exports: [CognitoService, JwtAuthGuard],
})
export class AuthModule {}
