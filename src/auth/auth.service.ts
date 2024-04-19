import { Injectable, UnauthorizedException } from '@nestjs/common';
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

  async loginWithEmail(user: Pick<User, 'email' | 'password'>) {
    const existingUser = await this.authenticateWithEmailAndPassword(user);
    return this.loginUser(existingUser);
  }

  extractTokenFromHeader(header: string, isBearer: boolean) {
    const splitToken = header.split(' ');
    const prefix = isBearer ? 'Bearer' : 'Basic';
    if (splitToken.length !== 2 || splitToken[0] !== prefix)
      throw new UnauthorizedException('wrong token');

    const token = splitToken[1];
    return token;
  }

  decodedBasicToken(base64String: string) {
    const decoded = Buffer.from(base64String, 'base64').toString('utf-8');
    console.log(decoded);
    const split = decoded.split(':');
    if (split.length !== 2) throw new UnauthorizedException('wrong token');
    const [email, password] = split;
    return {
      email,
      password,
    };
  }

  async authenticateWithEmailAndPassword(
    user: Pick<User, 'email' | 'password'>,
  ) {
    // 아이디가 존재하는지 확인
    const existingUser = await this.userService.getUserByEmail(user.email);
    if (!existingUser) throw new UnauthorizedException('not exist user');

    // 비밀번호가 맞는지 확인
    const passOk = await bcrypt.compare(user.password, existingUser.password);
    if (!passOk) throw new UnauthorizedException('the password does not match');

    return existingUser;
  }
}
