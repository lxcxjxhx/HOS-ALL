import React, { useState } from 'react';
import { Box, Input, Text, Button, ButtonText } from '@gluestack-ui/themed';
import { Trip } from '@/types';

interface TripFormProps {
  initialValues?: Partial<Trip>;
  onSubmit: (values: Omit<Trip, 'id' | 'createdAt'>) => void;
}

export const TripForm: React.FC<TripFormProps> = ({ initialValues, onSubmit }) => {
  const [title, setTitle] = useState(initialValues?.title || '');
  const [content, setContent] = useState(initialValues?.content || '');
  const [image, setImage] = useState(initialValues?.image || '');

  const handleSubmit = () => {
    onSubmit({ title, content, image });
  };

  return (
    <Box className="p-4">
      <Text className="text-lg font-bold mb-4">Add/Edit Trip</Text>
      <Input
        variant="outline"
        className="mb-4"
      >
        <Input.Input
          placeholder="Title"
          value={title}
          onChangeText={setTitle}
        />
      </Input>
      <Input
        variant="outline"
        className="mb-4"
      >
        <Input.Input
          placeholder="Content"
          value={content}
          onChangeText={setContent}
          multiline
        />
      </Input>
      <Input
        variant="outline"
        className="mb-4"
      >
        <Input.Input
          placeholder="Image URL"
          value={image}
          onChangeText={setImage}
        />
      </Input>
      <Button onPress={handleSubmit}>
        <ButtonText>Submit</ButtonText>
      </Button>
    </Box>
  );
};
