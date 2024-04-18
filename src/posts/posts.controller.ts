import { Body, Controller, Get, Post } from '@nestjs/common';
import { PostsService } from './posts.service';
import { CreatePostDto } from './dto';

@Controller('posts')
export class PostsController {
  constructor(private readonly postsService: PostsService) {}

  @Post()
  create(@Body() createPostDto: CreatePostDto) {
    return this.postsService.create(createPostDto);
  }

  @Get()
  findAll() {
    return this.postsService.findAll();
  }
}
