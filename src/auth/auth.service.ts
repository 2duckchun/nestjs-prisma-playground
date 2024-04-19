import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { CreateUserDto } from 'src/users/dto';
import { User } from 'src/users/entities/user.entity';
import { UsersService } from 'src/users/users.service';

@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly userService: UsersService,
  ) {}

  async registerWithEmail(user: CreateUserDto) {
    const hashedPassword = await bcrypt.hash(user.password, 10);
    const newUser = await this.userService.create({
      ...user,
      password: hashedPassword,
    });
    return this.loginUser(newUser);
  }

  loginUser(user: Pick<User, 'id' | 'email' | 'name'>) {
    return {
      username: user.name,
      accessToken: this.signToken({ id: user.id, email: user.email }, false),
      refreshToken: this.signToken({ id: user.id, email: user.email }, true),
    };
  }

  signToken(user: Pick<User, 'id' | 'email'>, isRefreshToken: boolean) {
    const payload = {
      email: user.email,
      sub: user.id,
      type: isRefreshToken ? 'refresh' : 'access',
    };

    return this.jwtService.sign(payload, {
      secret: 'test-jwt-key',
      expiresIn: isRefreshToken ? 3600 : 600,
    });
  }
}
