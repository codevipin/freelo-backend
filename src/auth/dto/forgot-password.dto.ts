import { IsEmail } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class ForgotPasswordDto {
  @ApiProperty({
    description: 'User email address',
    example: 'john.doe@example.com',
  })
  @IsEmail()
  email: string;
}

export class ConfirmForgotPasswordDto {
  @ApiProperty({
    description: 'User email address',
    example: 'john.doe@example.com',
  })
  @IsEmail()
  email: string;

  @ApiProperty({
    description: 'Confirmation code sent to email',
    example: '123456',
  })
  code: string;

  @ApiProperty({
    description: 'New password (minimum 8 characters)',
    example: 'newpassword123',
    minLength: 8,
  })
  newPassword: string;
}
