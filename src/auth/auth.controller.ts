import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto } from 'src/users/dto';

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
}
