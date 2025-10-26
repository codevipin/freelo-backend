export interface AuthResponse {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  tokenType: string;
}

export interface RegisterResponse {
  message: string;
  userId: string;
  email: string;
  requiresVerification: boolean;
}

export interface LoginResponse {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  tokenType: string;
  user: {
    id: string;
    email: string;
    name: string;
    phoneNumber: string;
    verified: boolean;
    type: string;
  };
}

export interface VerifyEmailResponse {
  message: string;
  verified: boolean;
}

export interface ForgotPasswordResponse {
  message: string;
}

export interface CognitoUser {
  id: string;
  email: string;
  name: string;
  phoneNumber: string;
  verified: boolean;
  type: string;
}
