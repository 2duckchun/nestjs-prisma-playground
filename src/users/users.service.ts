import { Injectable } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { PrismaService } from 'src/database/prisma.service';
// import { UpdateUserDto } from './dto/update-user.dto';

@Injectable()
export class UsersService {
  constructor(private prisma: PrismaService) {}

  async create(createUserDto: CreateUserDto) {
    return this.prisma.user.create({
      data: {
        email: createUserDto.email,
        name: createUserDto.name,
        password: createUserDto.password,
      },
    });
  }

  async getUserByEmail(email: string) {
    return await this.prisma.user.findFirst({
      where: {
        email: email,
      },
    });
  }

  findAll() {
    return this.prisma.user.findMany({
      include: {
        comments: {
          include: {
            post: true,
          },
        },
        follows: {
          include: {
            user: true,
          },
        },
        posts: {
          include: {
            author: true,
          },
        },
      },
    });
  }

  findOne(id: number) {
    return `This action returns a #${id} user`;
  }

  // update(id: number, updateUserDto: UpdateUserDto) {
  //   return `This action updates a #${id} user`;
  // }

  remove(id: number) {
    return `This action removes a #${id} user`;
  }
}
