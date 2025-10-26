import { IsEmail, IsNotEmpty, IsString, MinLength, IsPhoneNumber, IsEnum } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export enum UserType {
  CUSTOMER = 'customer',
  RESTAURANT = 'restaurant',
}

export class RegisterDto {
  @ApiProperty({
    description: 'User full name',
    example: 'John Doe',
  })
  @IsNotEmpty()
  @IsString()
  name: string;

  @ApiProperty({
    description: 'User email address',
    example: 'john.doe@example.com',
  })
  @IsEmail()
  email: string;

  @ApiProperty({
    description: 'User password (minimum 8 characters)',
    example: 'password123',
    minLength: 8,
  })
  @IsNotEmpty()
  @IsString()
  @MinLength(8)
  password: string;

  @ApiProperty({
    description: 'User phone number (optional)',
    example: '+1234567890',
    required: false,
  })
  @IsString()
  phoneNumber?: string;

  @ApiProperty({
    description: 'User type (customer or restaurant)',
    example: 'customer',
    enum: UserType,
  })
  @IsEnum(UserType)
  type: UserType;
}
