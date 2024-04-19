import { Body, Controller, Headers, Post, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto } from 'src/users/dto';
import { BasicTokenGuard } from './guard/basic-token-guard';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register/email')
  async postRegisterWithEmail(@Body() createUserDto: CreateUserDto) {
    return this.authService.registerWithEmail({
      email: createUserDto.email,
      name: createUserDto.name,
      password: createUserDto.password,
    });
  }

  @Post('login/email')
  @UseGuards(BasicTokenGuard)
  async postLoginWithEmail(@Headers('authorization') rawToken: string) {
    const token = this.authService.extractTokenFromHeader(rawToken, false);
    const credentials = this.authService.decodedBasicToken(token);
    return this.authService.loginWithEmail(credentials);
  }
}
